import shutil, os

appdir = r"C:\Users\安\AppData\Local\GitHubDesktop\app-3.5.11\resources\app"

# 恢复 main.js
main_bak = os.path.join(appdir, "main.js.bak")
main_js  = os.path.join(appdir, "main.js")
if os.path.exists(main_bak):
    shutil.copy2(main_bak, main_js)
    print(f"OK main.js: {os.path.getsize(main_js)} bytes")
else:
    print("main.js.bak not found")

# 恢复 renderer.js
rnd_bak = os.path.join(appdir, "renderer.js.bak")
rnd_js  = os.path.join(appdir, "renderer.js")
if os.path.exists(rnd_bak):
    shutil.copy2(rnd_bak, rnd_js)
    print(f"OK renderer.js: {os.path.getsize(rnd_js)} bytes")
else:
    print("renderer.js.bak not found")

print("DONE - now try opening GitHub Desktop")
