git clone https://github.com/Nanoquake/yquake2
cd yquake2
git submodule init
git submodule update
cd nano25519
python3 setup.py install
cd ..
sudo apt-get install libsdl2-2.0
sudo apt-get install libopenal-dev
export LDFLAGS="-L/usr/local/opt/openal-soft/lib"
export CPPFLAGS="-I/usr/local/opt/openal-soft/include"
wget https://github.com/CommodoreAmiga/Nanoquake-theme-mod/blob/e950344501322af1ce829526ddd$
mv pak16.pak release/baseq2
make
wget https://deponie.yamagi.org/quake2/idstuff/q2-314-demo-x86.exe
unzip q2-314-demo-x86.exe
rm q2-314-demo-x86.exe

