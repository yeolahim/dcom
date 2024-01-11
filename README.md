wmi

Установить зависимости

$ cd ./bootstrap/generated-dists/<distrowithversion>
$ ./bootstrap.sh

gnutls может быть проблемой, использовалась
https://github.com/gnutls/gnutls.git
$ git checkout 3.6.13

Make

$ ./configure --disable-python --without-ad-dc --disable-cups
$ make

Восстановить переписаные генерированные файлы и пересобрать снова

$ git checkout bin
$ make

Подготовка пакета

$ mkdir wmi
$ cp -L ./bin/wmic wmi
$ cp -L ./bin/wmis wmi
$ cp -L ./bin/winexe wmi
$ cd wmi

Копируем зависимые библиотеки, может понадобиться копировать gnutls отдельно. Можно скопировать и системные библиотеки, но libc, libpthread, librt могут быть не совместимы с целевой платформой

$ ldd wmic | awk '{print $3}' | grep '/samba/bin/' | xargs -I '{}' cp {} .

Установим RPATH на все бинарные файлы

$ ls | xargs -I '{}' patchelf --set-rpath '$ORIGIN' {}