#------------------------------------------------------------------------------#
# Инструмент администрирования Регистраторов Марки Dahua - v5 (02.10.2025)
#------------------------------------------------------------------------------#

Add-Type -AssemblyName System.Windows.Forms, System.Drawing
[System.Windows.Forms.Application]::EnableVisualStyles()

#------------------------------------------------------------------------------#
# Логирование
#------------------------------------------------------------------------------#
if ($PSScriptRoot) {
    $logFile = Join-Path $PSScriptRoot "dahua_toolkit.log"
} else {
    $logFile = "dahua_toolkit.log"
}
if (-not (Test-Path $logFile)) {
    New-Item -Path $logFile -ItemType File | Out-Null
}
function Write-Log([string]$msg) {
    "$((Get-Date).ToString('yyyy-MM-dd HH:mm:ss')) $msg" | Add-Content $logFile
}
Write-Log "=== Инструмент администрирования Регистраторов Марки Dahua - v5 (02.10.2025) ==="

#------------------------------------------------------------------------------#
# Игнорирование самоподписанных сертификатов
#------------------------------------------------------------------------------#
Add-Type @"
using System.Net;
using System.Security.Cryptography.X509Certificates;
public class TrustAllCertsPolicy : ICertificatePolicy {
    public bool CheckValidationResult(
        ServicePoint srvPoint, X509Certificate certificate,
        WebRequest request, int certificateProblem) { return true; }
}
"@ -ErrorAction SilentlyContinue
[System.Net.ServicePointManager]::CertificatePolicy = New-Object TrustAllCertsPolicy

#------------------------------------------------------------------------------#
# Конфигурация регистраторов (Title — для отображения)
#------------------------------------------------------------------------------#
$recorders = @(
@{ IP = "192.168.1.1"; Username = "admin"; Password = "password"; Title = "Название Регистратора 1" },
@{ IP = "192.168.1.2"; Username = "admin"; Password = "password"; Title = "Название Регистратора 2" },
@{ IP = "192.168.1.3"; Username = "admin"; Password = "password"; Title = "Название Регистратора 3" }
)
Write-Log ("Загружено устройств: {0}" -f $recorders.Count)

function Get-RecLabel {
    param([hashtable]$r)
    if ($r.ContainsKey('Title') -and $r.Title) { "{0} — {1}" -f $r.Title, $r.IP } else { "{0}" -f $r.IP }
}

#------------------------------------------------------------------------------#
# Вспомогательные функции API и CRUD
#------------------------------------------------------------------------------#
function Invoke-Dahua($IP,$User,$Pass,$Query) {
    $url = "https://$IP/cgi-bin/userManager.cgi?$Query"
    Write-Log ("API → {0}" -f $url)
    $cred = New-Object System.Management.Automation.PSCredential(
        $User,(ConvertTo-SecureString $Pass -AsPlainText -Force)
    )
    try { Invoke-RestMethod -Uri $url -Credential $cred -Method Get -ErrorAction Stop }
    catch { "Ошибка: $($_.Exception.Message)" }
}

# Универсальный CGI-вызов: /cgi-bin/<Cgi>?<Query>
function Invoke-DahuaCgi {
    param(
        [Parameter(Mandatory)] [string]$IP,
        [Parameter(Mandatory)] [string]$User,
        [Parameter(Mandatory)] [string]$Pass,
        [Parameter(Mandatory)] [string]$Cgi,
        [Parameter(Mandatory)] [string]$Query
    )
    $url = "https://{0}/cgi-bin/{1}?{2}" -f $IP, $Cgi, $Query
    Write-Log ("API → {0}" -f $url)
    $cred = New-Object System.Management.Automation.PSCredential(
        $User,(ConvertTo-SecureString $Pass -AsPlainText -Force)
    )
    try { Invoke-RestMethod -Uri $url -Credential $cred -Method Get -ErrorAction Stop }
    catch { "Ошибка: $($_.Exception.Message)" }
}

function Add-User       { param($r,$u,$p,$g,$s,$re) Invoke-Dahua $r.IP $r.Username $r.Password "action=addUser&user.Name=$u&user.Password=$p&user.Group=$g&user.Sharable=$s&user.Reserved=$re" }
function Remove-User    { param($r,$u)              Invoke-Dahua $r.IP $r.Username $r.Password "action=deleteUser&name=$u" }
function Change-UserPwd { param($r,$u,$o,$n)        Invoke-Dahua $r.IP $r.Username $r.Password "action=modifyPassword&name=$u&pwdOld=$o&pwd=$n" }

#------------------------------------------------------------------------------#
# Парсеры
#------------------------------------------------------------------------------#
# Простой key=value -> Hashtable
function Parse-KV {
    param([string]$raw)
    $h = @{}
    if ([string]::IsNullOrWhiteSpace($raw)) { return $h }
    foreach ($line in ($raw -split "`n")) {
        $line = $line.Trim()
        if ($line -match '^\s*([^=]+)=(.*)$') {
            $k = $Matches[1].Trim()
            $v = $Matches[2].Trim()
            $h[$k] = $v
        }
    }
    return $h
}

# Группировка по префиксу ключа до первого "." или "[" (для storageDevice factory.getCollect)
function Group-KVByPrefix {
    param([hashtable]$kv)
    $groups = @{}
    foreach ($fullKey in $kv.Keys) {
        $parts = $fullKey -split '[\.\[]', 2
        $prefix = if ($parts.Length -gt 0 -and $parts[0]) { $parts[0] } else { 'Other' }
        $suffix = if ($parts.Length -gt 1) { $parts[1] } else { '' }
        if (-not $groups.ContainsKey($prefix)) { $groups[$prefix] = @{} }
        $groups[$prefix][$suffix] = $kv[$fullKey]
    }
    return $groups
}

# Парсер пользователя/группы из userManager.cgi
function Parse-UsersWithGroup {
    param([string]$raw)
    if ([string]::IsNullOrWhiteSpace($raw)) { return @() }
    $lines = ($raw -split "`n") | ForEach-Object { $_.Trim() }
    $byIndex = @{}
    foreach ($line in $lines) {
        if ($line -match '^users\[(\d+)\]\.([A-Za-z]+)=(.*)$') {
            $idx   = [int]$Matches[1]
            $field = ($Matches[2]).ToLowerInvariant()
            $val   = ($Matches[3]).Trim()
            if (-not $byIndex.ContainsKey($idx)) {
                $byIndex[$idx] = [ordered]@{ Name = $null; Group = $null }
            }
            switch ($field) {
                'name'  { $byIndex[$idx].Name  = $val }
                'group' { $byIndex[$idx].Group = $val }
                default { }
            }
        }
    }
    $users = foreach ($k in ($byIndex.Keys | Sort-Object)) {
        $rec = $byIndex[$k]
        if ($rec.Name) {
            [pscustomobject]@{
                Name  = $rec.Name.Trim()
                Group = if ($rec.Group) { $rec.Group.Trim() } else { '' }
            }
        }
    }
    return $users
}

#------------------------------------------------------------------------------#
# Проверка наличия пользователя
#------------------------------------------------------------------------------#
function Test-DahuaUserExists {
    [CmdletBinding()]
    param(
        [Parameter(Mandatory)][hashtable]$Recorder,
        [Parameter(Mandatory)][string]$Name,
        [switch]$ActiveOnly
    )

    $query = if ($ActiveOnly.IsPresent) { "action=getActiveUserInfoAll" } else { "action=getUserInfoAll" }
    $raw = Invoke-Dahua $Recorder.IP $Recorder.Username $Recorder.Password $query

    if ($raw -is [string] -and $raw.TrimStart() -like "Ошибка:*") {
        return [pscustomobject]@{
            Exists     = $false; Error = $raw; Name = $Name; Group = $null
            ActiveOnly = [bool]$ActiveOnly; IP = $Recorder.IP; Title = $Recorder.Title
        }
    }

    $users = Parse-UsersWithGroup ([string]$raw)
    $searchName = $Name.Trim()
    $match = $users | Where-Object { ($_.Name.Trim()) -ieq $searchName } | Select-Object -First 1

    if ($match) {
        [pscustomobject]@{
            Exists=$true;  Error=$null; Name=$match.Name.Trim(); Group=$match.Group
            ActiveOnly=[bool]$ActiveOnly; IP=$Recorder.IP; Title=$Recorder.Title
        }
    } else {
        [pscustomobject]@{
            Exists=$false; Error=$null; Name=$searchName; Group=$null
            ActiveOnly=[bool]$ActiveOnly; IP=$Recorder.IP; Title=$Recorder.Title
        }
    }
}

#------------------------------------------------------------------------------#
# Write-LogView
#------------------------------------------------------------------------------#
function Write-LogView($ip,$title,$action,$result) {
    $item=$lv.Items.Add((Get-Date -Format 'HH:mm:ss'))
    $null = $item.SubItems.Add($ip)
    $null = $item.SubItems.Add($title)
    $null = $item.SubItems.Add($action)
    $null = $item.SubItems.Add([string]$result)
    Write-Log ("[{0}][{1}] {2} → {3}" -f $ip,$title,$action,$result)
}

#------------------------------------------------------------------------------#
# Построение GUI
#------------------------------------------------------------------------------#
$form = New-Object System.Windows.Forms.Form -Property @{
    Text          = "Инструмент администрирования Регистраторов Марки Dahua - v5 (22.08.2025)"
    ClientSize    = New-Object Drawing.Size(1000,640)
    StartPosition = 'CenterScreen'
    AutoScaleMode = 'Font'
}

# GroupBox «Настройки»
$grp = New-Object System.Windows.Forms.GroupBox -Property @{
    Text   = "Настройки"
    Location = New-Object Drawing.Point(10,10)
    Size     = New-Object Drawing.Size(980,150)
    Anchor   = 'Top,Left,Right'
}
$form.Controls.Add($grp)

# Поля
$lblU  = New-Object System.Windows.Forms.Label   -Property @{Text="Имя пользователя:"; Location=New-Object Drawing.Point(10,30); AutoSize=$true}
$txtU  = New-Object System.Windows.Forms.TextBox -Property @{Name="txtUser";          Location=New-Object Drawing.Point(130,27); Size=New-Object Drawing.Size(200,22)}

$lblP  = New-Object System.Windows.Forms.Label   -Property @{Text="Пароль (старый):"; Location=New-Object Drawing.Point(350,30); AutoSize=$true}
$txtP  = New-Object System.Windows.Forms.TextBox -Property @{Name="txtPass"; UseSystemPasswordChar=$true; Location=New-Object Drawing.Point(460,27); Size=New-Object Drawing.Size(180,22)}

$lblNP = New-Object System.Windows.Forms.Label   -Property @{Text="Новый пароль:";    Location=New-Object Drawing.Point(650,30); AutoSize=$true}
$txtNP = New-Object System.Windows.Forms.TextBox -Property @{Name="txtNewPass"; UseSystemPasswordChar=$true; Location=New-Object Drawing.Point(740,27); Size=New-Object Drawing.Size(230,22)}

$lblG  = New-Object System.Windows.Forms.Label   -Property @{Text="Группа:";          Location=New-Object Drawing.Point(10,65); AutoSize=$true}
$cmbG  = New-Object System.Windows.Forms.ComboBox -Property @{Name="cmbGroup"; DropDownStyle='DropDownList'; Location=New-Object Drawing.Point(130,62); Size=New-Object Drawing.Size(200,22)}
$cmbG.Items.AddRange(@("admin","user"))|Out-Null
$chkM  = New-Object System.Windows.Forms.CheckBox -Property @{Text="Многопользовательский"; Location=New-Object Drawing.Point(350,62); AutoSize=$true}
$chkD  = New-Object System.Windows.Forms.CheckBox -Property @{Text="Удаляемый?";           Location=New-Object Drawing.Point(350,90); AutoSize=$true}
$grp.Controls.AddRange(@($lblU,$txtU,$lblP,$txtP,$lblNP,$txtNP,$lblG,$cmbG,$chkM,$chkD))

# Кнопки
$btnAdd  = New-Object System.Windows.Forms.Button -Property @{Text="Добавить";             Size=New-Object Drawing.Size(100,30); Location=New-Object Drawing.Point(10,110)}
$btnRem  = New-Object System.Windows.Forms.Button -Property @{Text="Удалить";              Size=New-Object Drawing.Size(100,30); Location=New-Object Drawing.Point(120,110)}
$btnPwd  = New-Object System.Windows.Forms.Button -Property @{Text="Сменить пароль";       Size=New-Object Drawing.Size(120,30); Location=New-Object Drawing.Point(230,110)}
$btnUpd  = New-Object System.Windows.Forms.Button -Property @{Text="Список Пользователей"; Size=New-Object Drawing.Size(150,30); Location=New-Object Drawing.Point(360,110)}
$btnFind = New-Object System.Windows.Forms.Button -Property @{Text="Поиск";                Size=New-Object Drawing.Size(90,30);  Location=New-Object Drawing.Point(520,110)}
$btnInfo = New-Object System.Windows.Forms.Button -Property @{Text="Инфо";                 Size=New-Object Drawing.Size(90,30);  Location=New-Object Drawing.Point(620,110)}
$grp.Controls.AddRange(@($btnAdd,$btnRem,$btnPwd,$btnUpd,$btnFind,$btnInfo))

# Чекбокс «Только активные»
$chkActiveOnly = New-Object System.Windows.Forms.CheckBox -Property @{
    Text     = "Только активные"
    Location = New-Object Drawing.Point(720,115)
    AutoSize = $true
    Anchor   = 'Top,Left'
}
$grp.Controls.Add($chkActiveOnly)

# Список устройств
$clb = New-Object System.Windows.Forms.CheckedListBox -Property @{
    CheckOnClick = $true
    Location     = New-Object Drawing.Point(10,200)
    Size         = New-Object Drawing.Size(260,230)
    Anchor       = 'Top,Left,Bottom'
}
foreach($r in $recorders){ $null = $clb.Items.Add((Get-RecLabel $r)) }
$form.Controls.Add($clb)

# Дерево результатов
$tv = New-Object System.Windows.Forms.TreeView -Property @{
    Location   = New-Object Drawing.Point(280,200)
    Size       = New-Object Drawing.Size(700,230)
    Anchor     = 'Top,Left,Right,Bottom'
    Scrollable = $true
}
$form.Controls.Add($tv)

# Логи
$lv = New-Object System.Windows.Forms.ListView -Property @{
    View          = 'Details'
    FullRowSelect = $true
    GridLines     = $true
    Location      = New-Object Drawing.Point(10,480)
    Size          = New-Object Drawing.Size(980,150)
    Anchor        = 'Left,Right,Bottom'
}
$null = $lv.Columns.Add("Время",90)
$null = $lv.Columns.Add("Регистратор",110)
$null = $lv.Columns.Add("Объект",220)
$null = $lv.Columns.Add("Действие",300)
$null = $lv.Columns.Add("Результат",240)
$form.Controls.Add($lv)

#------------------------------------------------------------------------------#
# Обработчики кнопок
#------------------------------------------------------------------------------#
$btnAdd.Add_Click({
    if($clb.CheckedItems.Count -eq 0){ [Windows.Forms.MessageBox]::Show("Выберите устройство","Ошибка") | Out-Null; return }
    foreach($i in $clb.CheckedIndices){
        $r=$recorders[$i]
        $res=Add-User $r $txtU.Text $txtP.Text $cmbG.Text $chkM.Checked $chkD.Checked
        Write-LogView $r.IP $r.Title ("Добавить пользователя '{0}'" -f $txtU.Text) $res
    }
})

$btnRem.Add_Click({
    if($clb.CheckedItems.Count -eq 0){ [Windows.Forms.MessageBox]::Show("Выберите устройство","Ошибка") | Out-Null; return }
    foreach($i in $clb.CheckedIndices){
        $r=$recorders[$i]
        $res=Remove-User $r $txtU.Text
        Write-LogView $r.IP $r.Title ("Удалить пользователя '{0}'" -f $txtU.Text) $res
    }
})

$btnPwd.Add_Click({
    if($clb.CheckedItems.Count -eq 0){ [Windows.Forms.MessageBox]::Show("Выберите устройство","Ошибка") | Out-Null; return }
    $old = $txtP.Text; $new = $txtNP.Text
    if([string]::IsNullOrWhiteSpace($old) -or [string]::IsNullOrWhiteSpace($new)){
        [Windows.Forms.MessageBox]::Show("Укажите старый и новый пароль в полях сверху.","Ошибка") | Out-Null
        return
    }
    foreach($i in $clb.CheckedIndices){
        $r=$recorders[$i]
        $res=Change-UserPwd $r $txtU.Text $old $new
        Write-LogView $r.IP $r.Title ("Сменить пароль пользователя '{0}'" -f $txtU.Text) $res
    }
    $txtNP.Clear()
})

$btnUpd.Add_Click({
    if($clb.CheckedItems.Count -eq 0){ [Windows.Forms.MessageBox]::Show("Выберите устройство","Ошибка") | Out-Null; return }
    $tv.BeginUpdate()
    try {
        $tv.Nodes.Clear()
        foreach($i in $clb.CheckedIndices){
            $r=$recorders[$i]
            $all=Parse-UsersWithGroup (Invoke-Dahua $r.IP $r.Username $r.Password "action=getUserInfoAll")
            $act=Parse-UsersWithGroup (Invoke-Dahua $r.IP $r.Username $r.Password "action=getActiveUserInfoAll")
            $node=New-Object System.Windows.Forms.TreeNode (Get-RecLabel $r)
            if($chkActiveOnly.Checked){
                $na=New-Object System.Windows.Forms.TreeNode "Активные пользователи"
                foreach($u in $act){ $null = $na.Nodes.Add(("{0} ({1})" -f $u.Name, $u.Group)) }
                $null = $node.Nodes.Add($na)
            } else {
                $na=New-Object System.Windows.Forms.TreeNode "Все пользователи"
                foreach($u in $all){ $null = $na.Nodes.Add(("{0} ({1})" -f $u.Name, $u.Group)) }
                $null = $node.Nodes.Add($na)
            }
            $null = $tv.Nodes.Add($node)
            Write-LogView $r.IP $r.Title "Запрос списка" "OK"
        }
    } finally {
        $tv.EndUpdate(); $tv.ExpandAll(); $tv.Focus()
    }
})

$btnFind.Add_Click({
    if([string]::IsNullOrWhiteSpace($txtU.Text)){
        [Windows.Forms.MessageBox]::Show("Введите имя пользователя для поиска","Ошибка") | Out-Null; return
    }
    if($clb.CheckedItems.Count -eq 0){
        [Windows.Forms.MessageBox]::Show("Выберите устройство","Ошибка") | Out-Null; return
    }
    $tv.BeginUpdate()
    try {
        $tv.Nodes.Clear()
        foreach($i in $clb.CheckedIndices){
            $r = $recorders[$i]
            $res = if ($chkActiveOnly.Checked) {
                Test-DahuaUserExists -Recorder $r -Name $txtU.Text -ActiveOnly
            } else {
                Test-DahuaUserExists -Recorder $r -Name $txtU.Text
            }
            $msg = if ($res.Error) { $res.Error } elseif ($res.Exists) { "Найден (группа: {0})" -f $res.Group } else { "Не найден" }
            $null = $tv.Nodes.Add( (New-Object System.Windows.Forms.TreeNode( ("{0}: {1}" -f (Get-RecLabel $r), $msg) )) )
            $scope = if ($chkActiveOnly.Checked) { " (активные)" } else { "" }
            Write-LogView $r.IP $r.Title ("Поиск пользователя '{0}'{1}" -f $txtU.Text, $scope) $msg
        }
    } finally {
        $tv.EndUpdate(); $tv.ExpandAll(); $tv.Focus()
    }
})

# Инфо: время, тип, SN, HW, имя, вендор, версия ПО, системная инфа, Хранилище
$btnInfo.Add_Click({
    if ($clb.CheckedItems.Count -eq 0) {
        [Windows.Forms.MessageBox]::Show("Выберите устройство","Ошибка") | Out-Null
        return
    }

    $tv.BeginUpdate()
    try {
        $tv.Nodes.Clear()
        foreach ($i in $clb.CheckedIndices) {
            $r = $recorders[$i]

            # --- Корректные API
            $timeRaw = Invoke-DahuaCgi $r.IP $r.Username $r.Password "global.cgi"     "action=getCurrentTime"
            $devTypeRaw = Invoke-DahuaCgi $r.IP $r.Username $r.Password "magicBox.cgi" "action=getDeviceType"
            $hwVerRaw   = Invoke-DahuaCgi $r.IP $r.Username $r.Password "magicBox.cgi" "action=getHardwareVersion"
            $snRaw      = Invoke-DahuaCgi $r.IP $r.Username $r.Password "magicBox.cgi" "action=getSerialNo"
            $nameRaw    = Invoke-DahuaCgi $r.IP $r.Username $r.Password "magicBox.cgi" "action=getMachineName"
            $vendRaw    = Invoke-DahuaCgi $r.IP $r.Username $r.Password "magicBox.cgi" "action=getVendor"
            $swVerRaw   = Invoke-DahuaCgi $r.IP $r.Username $r.Password "magicBox.cgi" "action=getSoftwareVersion"
            $sysRaw     = Invoke-DahuaCgi $r.IP $r.Username $r.Password "magicBox.cgi" "action=getSystemInfo"

            # --- Хранилище
            $storRaw    = Invoke-DahuaCgi $r.IP $r.Username $r.Password "storageDevice.cgi" "action=factory.getCollect"

            # Парсим key=value
            $kvTime = Parse-KV ([string]$timeRaw)
            $kvType = Parse-KV ([string]$devTypeRaw)
            $kvHW   = Parse-KV ([string]$hwVerRaw)
            $kvSN   = Parse-KV ([string]$snRaw)
            $kvName = Parse-KV ([string]$nameRaw)
            $kvVend = Parse-KV ([string]$vendRaw)
            $kvSW   = Parse-KV ([string]$swVerRaw)
            $kvSys  = Parse-KV ([string]$sysRaw)
            $kvStor = Parse-KV ([string]$storRaw)

            $root = New-Object System.Windows.Forms.TreeNode (Get-RecLabel $r)

            # Время
            $nTime = New-Object System.Windows.Forms.TreeNode "Дата/Время"
            if ($kvTime.Keys.Count -gt 0) {
                foreach ($k in $kvTime.Keys) { [void]$nTime.Nodes.Add( ("{0}: {1}" -f $k, $kvTime[$k]) ) }
            } else {
                [void]$nTime.Nodes.Add( [string]$timeRaw )
            }
            [void]$root.Nodes.Add($nTime)

            # Основные параметры
            $nMain = New-Object System.Windows.Forms.TreeNode "Основные параметры"
            function _AddKVNode { param($ht, $title)
                if ($ht -and $ht.Keys.Count -gt 0) {
                    $n = New-Object System.Windows.Forms.TreeNode $title
                    foreach ($k in $ht.Keys) { [void]$n.Nodes.Add( ("{0}: {1}" -f $k, $ht[$k]) ) }
                    return $n
                } else { return $null }
            }
            foreach ($node in @(
                (_AddKVNode $kvType "Тип устройства"),
                (_AddKVNode $kvHW   "Аппаратная версия"),
                (_AddKVNode $kvSN   "Серийный номер"),
                (_AddKVNode $kvName "Имя устройства"),
                (_AddKVNode $kvVend "Производитель"),
                (_AddKVNode $kvSW   "Версия ПО")
            )) { if ($node -ne $null) { [void]$nMain.Nodes.Add($node) } }
            if ($nMain.Nodes.Count -eq 0) { [void]$nMain.Nodes.Add("Нет данных") }
            [void]$root.Nodes.Add($nMain)

            # Системная информация
            $nSys = New-Object System.Windows.Forms.TreeNode "Системная информация"
            if ($kvSys.Keys.Count -gt 0) {
                $pref = @('DeviceType','DeviceName','SerialNo','Version','BuildDate','HardwareVersion','CPUInfo','UpTime','MAC','IPAddress','SN')
                $shown = New-Object System.Collections.Generic.HashSet[string]
                foreach ($p in $pref) {
                    if ($kvSys.ContainsKey($p)) {
                        [void]$nSys.Nodes.Add( ("{0}: {1}" -f $p, $kvSys[$p]) )
                        $null = $shown.Add($p)
                    }
                }
                foreach ($k in $kvSys.Keys) {
                    if (-not $shown.Contains($k)) { [void]$nSys.Nodes.Add( ("{0}: {1}" -f $k, $kvSys[$k]) ) }
                }
            } else {
                [void]$nSys.Nodes.Add( [string]$sysRaw )
            }
            [void]$root.Nodes.Add($nSys)

            # Хранилище
            $nStor = New-Object System.Windows.Forms.TreeNode "Хранилище"
            if ($kvStor.Keys.Count -gt 0) {
                $groups = Group-KVByPrefix $kvStor
                foreach ($g in ($groups.Keys | Sort-Object)) {
                    $nGrp = New-Object System.Windows.Forms.TreeNode $g
                    foreach ($k in ($groups[$g].Keys | Sort-Object)) {
                        $displayKey = if ([string]::IsNullOrWhiteSpace($k)) { $g } else { $k }
                        [void]$nGrp.Nodes.Add( ("{0}: {1}" -f $displayKey, $groups[$g][$k]) )
                    }
                    [void]$nStor.Nodes.Add($nGrp)
                }
            } else {
                [void]$nStor.Nodes.Add( [string]$storRaw )
            }
            [void]$root.Nodes.Add($nStor)

            [void]$tv.Nodes.Add($root)
            Write-LogView $r.IP $r.Title "Информация об Устройстве" "OK"
        }
    } catch {
        Write-LogView "-" "-" "Информация об Устройстве" ("Ошибка: {0}" -f $_.Exception.Message)
    } finally {
        $tv.EndUpdate(); $tv.ExpandAll(); $tv.Focus()
    }
})

#------------------------------------------------------------------------------#
# Запуск формы
#------------------------------------------------------------------------------#
$form.ShowDialog() | Out-Null
Write-Log "=== Выход ==="
