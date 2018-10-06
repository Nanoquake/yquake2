echo "Installing Nanoquake"
git submodule init
git submodule update
cd simple-crypt
python3 setup.py install
cd ..
cd nano25519
python3 setup.py install
cd ..

pip3 install -r requirements.txt

brew install sdl2 openal-soft

export LDFLAGS="-L/usr/local/opt/openal-soft/lib"
export CPPFLAGS="-I/usr/local/opt/openal-soft/include"

make

wget https://deponie.yamagi.org/quake2/idstuff/q2-314-demo-x86.exe
unzip q2-314-demo-x86.exe
rm q2-314-demo-x86.exe
cd Install/Data/baseq2
cp pak0.pak ../../../release/baseq2/
cp -a players ../../../release/baseq2/
cd ../../../
echo "Installation Complete"
