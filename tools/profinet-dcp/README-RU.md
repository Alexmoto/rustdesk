# Автоматический PROFINET DCP при TCP 102 (Windows)

## Поведение
При создании обычного TCP Port Forward в RustDesk с Remote Port = 102:
1. RustDesk оставляет штатный TCP-проброс порта 102 без изменений.
2. В той же авторизованной сессии автоматически поднимается скрытый TCP-канал DCP с локальным динамическим портом и удалённым loopback 127.0.0.1:49092.
3. Локальный вспомогательный процесс (включён в папку Release) отслеживает DCP Identify на активных Npcap-интерфейсах. Это важно для TIA Portal внутри VirtualBox.
4. Удалённый RustDesk запускает тот же помощник только после авторизации IP tunneling. Интерфейс, ведущий к PLC, выбирается по маршруту к Remote Host TCP-проброса.
5. DCP Identify передаётся удалённому контроллеру, а ответы возвращаются в стек локального ПК через Npcap.
6. При удалении последнего проброса TCP 102 локальный помощник и скрытый канал закрываются.

В окне Port Forwarding при Remote Port 102 появляется сообщение:
PROFINET DCP: автопроброс при TCP 102 (Npcap на обоих ПК).

Важно: сообщение означает запрошенный автозапуск, а не подтверждённую связь с PLC. Для определения ошибок смотрите журнал. Это только DCP Identify, не L2 VPN, не DCP Set, не PROFINET IO real-time.

## Условия
- На обоих Windows-компьютерах установлена одинаковая модифицированная версия RustDesk (достаточно всей папки flutter/build/windows/x64/runner/Release).
- Npcap 1.83+ установлен на обеих машинах, с доступом к захвату для процесса RustDesk.
- В TCP-пробросе Remote Host укажите IP самого контроллера, например 192.168.0.10, а Remote Port = 102.
- В TIA Portal должен быть выбран интерфейс, на котором реально появляются DCP Identify; локальный помощник прослушивает все активные Npcap-адаптеры.
- Автоматическое обнаружение удалённого интерфейса по маршруту предполагает одну однозначную сетевую карту для IP ПЛК. Если карты неоднозначны, автопроброс не будет угадывать адаптер.

## Сборка Windows
Из корня проекта в PowerShell (в подготовленном окружении Rust, Flutter, vcpkg, LLVM):

    python -m pip install pyinstaller
    python -m unittest discover -s tools\profinet-dcp -p "test_*.py" -v
    python .\build.py --portable --flutter --skip-portable-pack --hwcodec

Скрипт build.py сам формирует onedir сборку Python-помощника через PyInstaller и помещает его в

    flutter\build\windows\x64\runner\Release\rustdesk-profinet-dcp\

Ни Python, ни PyInstaller на второй машине не нужны. Npcap нужен.

## Диагностика
Журнал процесса в обычном сеансе:

    %LOCALAPPDATA%\RustDesk\profinet-dcp.log

Если удалённый RustDesk запущен системной службой, возможен путь:

    C:\Windows\System32\config\systemprofile\AppData\Local\RustDesk\profinet-dcp.log

Проверить Windows на второй машине:

    Get-NetAdapter | Select-Object Name, Status, InterfaceGuid, MacAddress
    Get-NetIPAddress -AddressFamily IPv4
    Get-NetRoute -AddressFamily IPv4

Если маршрут неоднозначен, можно задать переменную окружения процесса удалённого RustDesk RUSTDESK_DCP_REMOTE_GUID равной InterfaceGuid адаптера, подключённого к PLC. Перезапустите RustDesk / службу, чтобы она получила новое значение. Настройка не передаётся от локального ПК.

## Ограничения первой встроенной версии
- Одно активное удалённое подключение DCP на процесс RustDesk; другое направление/сеть потребует завершения текущего моста.
- DCP-пакеты с VLAN тегом не поддерживаются.
- Дополнительный канал требует разрешения IP Tunneling; отдельные порты в интернет открывать не нужно.
- Фактический тест Windows RustDesk + VirtualBox TIA Portal + PLC должен быть выполнен после новой сборки. Автономные Python-тесты не заменяют испытание на аппаратуре.
