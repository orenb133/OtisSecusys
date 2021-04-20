import PyInstaller.__main__
import os
import shutil

# Paths
basePath = os.path.realpath(os.path.join(os.path.dirname(__file__), os.path.pardir))
srcPath = os.path.join(basePath, 'src')
outPath = os.path.join(basePath, 'out')
workPath = os.path.join(outPath, 'work')

# Bundle
PyInstaller.__main__.run([
    '--clean',
    '--onefile',
    '--workpath', workPath,
    '--distpath', outPath,
    '--hidden-import', 'win32timezone',
    os.path.join(srcPath, 'service.py'),
    os.path.join(srcPath, 'bridge.py'),
])

# Copy config files
shutil.copy2(os.path.join(srcPath, 'bridge.cfg'), outPath)
shutil.copy2(os.path.join(srcPath, 'groups.cfg'), outPath)

# Remove build artifacts
shutil.rmtree(workPath)