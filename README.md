# **Antivirus**

Данный антивирус является улучшенной версией 1 антивируса, который мог уничтожать только целенаправленные вирусы.

В данном антивирусе достаточно прописать необходимый путь до места появления вирусного файла.

# Принцип работы:
- При 1 запуске происходит копирование exe файла антивируса в папку C:/antivirus, а также добавление в реестр автозапуска. После этого запускается файл из C:/antivirus
- Запускает 12 секундный цикл: выключение процессов, 2 секунды ожидания, удаление файлов, 10 секунд сна. 

# Список вирусов, от которых имеется защита:
- smss.exe, распространяющийся через флешку и сохраняющий себя на C:/Users/{user}
- [USB-VIRUS](https://github.com/Yukaii/USB-VIRUS), также распространяющий себя через флешку и сохраняющий себя в C:/Users/{user}/AppData/Roaming/WindowsServices под аттрибутами +A +H +S +I (включая папку)

# Для редактирования кода:
- Проект должен быть обязательно на стандарте языка C++ 17 версии
- Также может потребовться изменение набора инструмента платформы. В проекте используется 143 версия, а также тестировалось на 142. 
- Если вы хотите добавить путь до вируса, необходимо прописать его в файле Catcher.h

# Скачать: [executable.zip](https://github.com/Statuxia/Antivirus/files/11125834/executable.zip)
