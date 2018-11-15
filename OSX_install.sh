echo "Installing Nanoquake"
git submodule init
git submodule update
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

cd release/baseq2
mkdir maps
cd maps
wget http://www.andrewbullock.net/quake2/q2files/tourney/maps/q2dm1.bsp
wget http://www.andrewbullock.net/quake2/q2files/tourney/maps/ztn2dm1.bsp
cd ../../../

cd nanoquake_theme_mod/
cp pak16.pak ../release/baseq2/
cd ../
echo "Installation Complete"
