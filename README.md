# Dahua Admin Toolkit (PowerShell GUI)

Инструмент для администрирования регистраторов **Dahua** через WinForms-GUI: управление пользователями, смена паролей, быстрый поиск, просмотр характеристик устройства (Cloud ID, версии ПО/железа, текущее время, серийный номер, диски и пр.), логирование операций.

> Скрипт рассчитан на локальную работу администратора в доверенной сети. Вызовы выполняются к штатным CGI-API Dahua.

---

## 📌 Возможности

- **Пользователи**
  - Просмотр списка (все / только активные)
  - Поиск пользователя на выбранных устройствах
  - Добавление и удаление пользователя
  - Смена пароля (старый — из «Пароль», новый — из «Новый пароль»)
- **Информация об устройстве**
  - Текущее время, тип/вендор/модель, серийный номер
  - Версии ПО/железа, имя хоста, системная информация
  - Сводка по хранилищам (диски/слоты), если поддерживается прошивкой
- **Интерфейс**
  - Список устройств слева — «Название — IP»
  - Центральное дерево с результатами запросов
  - Нижний лог с колонками: Время, IP, Объект (Title), Действие, Результат
- **Прочее**
  - Игнорирование самоподписанных сертификатов (опционально)
  - Устойчивый парсер ответов `userManager.cgi`
  - Безопасная работа с паролями через SecretManagement/DPAPI

---

## 🧰 Требования

- Windows PowerShell **5.1** или PowerShell **7.x**
- .NET WinForms (входит в состав Windows)
- Доступ по сети к регистраторам Dahua

---
## 🚀 Установка и запуск
``` 
git clone https://github.com/xor0x1/Dahua-Admin-Toolkit.git]
cd Dahua-Admin-Toolkit
```
- Windows PowerShell
> powershell.exe -ExecutionPolicy Bypass -File .\DahuaAdminToolkit_v5.ps1

- или PowerShell 7+
> pwsh -File .\DahuaAdminToolkit.ps1
---
## ⚙️ Конфигурация устройств
В начале скрипта задаётся массив регистраторов. Поле Title — только для отображения в UI.
```powershell
@{ IP = "192.168.1.1"; Username = "admin"; Password = "password"; Title = "Название Регистратора 1" },
@{ IP = "192.168.1.2"; Username = "admin"; Password = "password"; Title = "Название Регистратора 2" },
@{ IP = "192.168.1.3"; Username = "admin"; Password = "password"; Title = "Название Регистратора 3" }
```
---
## 🌐 Поддерживаемые Dahua CGI

- **Пользователи**

  - GET /cgi-bin/userManager.cgi?action=getUserInfoAll
  - GET /cgi-bin/userManager.cgi?action=getActiveUserInfoAll
  - GET /cgi-bin/userManager.cgi?action=addUser&user.Name=...&user.Password=...&user.Group=...&user.Sharable=...&user.Reserved=...
  - GET /cgi-bin/userManager.cgi?action=deleteUser&name=...
  - GET /cgi-bin/userManager.cgi?action=modifyPassword&name=...&pwdOld=...&pwd=...

- **Информация об устройстве**

  - GET /cgi-bin/global.cgi?action=getCurrentTime
  - GET /cgi-bin/magicBox.cgi?action=getDeviceType
  - GET /cgi-bin/magicBox.cgi?action=getHardwareVersion
  - GET /cgi-bin/magicBox.cgi?action=getSerialNo
  - GET /cgi-bin/magicBox.cgi?action=getMachineName
  - GET /cgi-bin/magicBox.cgi?action=getSystemInfo
  - GET /cgi-bin/magicBox.cgi?action=getVendor
  - GET /cgi-bin/magicBox.cgi?action=getSoftwareVersion

- **Хранилище**

  - GET /cgi-bin/storageDevice.cgi?action=factory.getCollect (наличие зависит от модели/прошивки)

> Набор и формат ответов зависят от модели и версии прошивки Dahua.
---
## 🖱️ Использование
- Отметьте устройства слева (чекбоксы «Название — IP»).
- В блоке «Настройки» заполните:
  - «Имя пользователя»
  - «Пароль» — для добавления и как старый при смене
  - «Новый пароль» — поле для нового при смене
  - «Группа» — admin / user
  - «Многопользовательский», «Удаляемый?» — по необходимости

- Кнопки:
  - Список пользователей — выводит дерево (все/активные — по галке «Только активные»)
  - Поиск — «Найден (группа: …)» или «Не найден»
  - Добавить / Удалить пользователя
  - Сменить пароль — использует поля «Пароль» и «Новый пароль»
- Характеристики — вывод System / Cloud / Disks (если доступны)
- Внизу — журнал действий: Время, IP, Объект, Действие, Результат.
---

## 🖼️ Скриншоты
<img width="1009" height="673" alt="изображение" src="https://github.com/user-attachments/assets/8d4bd102-651e-4099-9969-b9fb32a098a3" />

---

## 🔒 Безопасность

 - Не храните пароли в коде/репозитории.
 - Ограничьте доступ к рабочей станции и профилю пользователя.
---

## 🗺️ Доработки / Roadmap (Планируется)

- Безопасное хранение учётных данных (SecretManagement + SecretStore, DPAPI)
- Экспорт списков и логов в CSV/Excel
- Параллельные запросы к устройствам
- Профили/группы устройств
- Доп. эндпоинты (сеть, NTP, PTZ, каналы и т.п.)
- Локализация UI (EN)
---
## ⚠️ Отказ от ответственности

- Инструмент не является официальным продуктом Dahua. Используйте на свой риск.
- Проверяйте совместимость с вашей моделью/прошивкой на тестовом стенде перед массовым применением.
