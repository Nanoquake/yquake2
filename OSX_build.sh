python3.7 -m PyInstaller start.py --add-binary='/System/Library/Frameworks/Tk.framework/Tk':'tk' --add-binary='/System/Library/Frameworks/Tcl.framework/Tcl':'tcl'

cp -a locale dist/start/

cp -a /Library/Frameworks/Python.framework/Versions/3.7/lib/tcl8.6 dist/start/

cp -a /Library/Frameworks/Python.framework/Versions/3.7/lib/tk8.6 dist/start/

cp -a release dist/start/

mv dist/start/start dist/start/NanoQuake

cd dist/start/release/

install_name_tool -change  /usr/local/opt/sdl2/lib/libSDL2-2.0.0.dylib @executable_path/libSDL2-2.0.0.dylib quake2

install_name_tool -change /usr/local/opt/sdl2/lib/libSDL2-2.0.0.dylib @executable_path/libSDL2-2.0.0.dylib ref_gl1.dylib
install_name_tool -change /usr/local/opt/sdl2/lib/libSDL2-2.0.0.dylib @executable_path/libSDL2-2.0.0.dylib ref_gl3.dylib
install_name_tool -change /usr/local/opt/sdl2/lib/libSDL2-2.0.0.dylib @executable_path/libSDL2-2.0.0.dylib ref_soft.dylib

cd ../../../

rm dist/start/release/baseq2/pak0.pak
rm -r dist/start/release/baseq2/players


mv dist/start dist/NanoQuake1.6OSX
