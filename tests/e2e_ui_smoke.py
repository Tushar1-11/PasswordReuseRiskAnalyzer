"""Optional browser smoke test (needs: pip install playwright && playwright install chromium).
Run from the project root:  python tests/e2e_ui_smoke.py
Not part of the unit-test run; it drives the real UI incl. an XSS payload, import, rotate and erase."""
import sys, os, threading, tempfile
sys.path.insert(0, os.getcwd())
from werkzeug.serving import make_server
from app import create_app
from reuse_analyzer import Settings
from playwright.sync_api import sync_playwright, expect

d = tempfile.mkdtemp()
app = create_app({"DATABASE": d+"/t.db", "SECRET_FILE": d+"/k", "SETTINGS": Settings(scrypt_log_n=10)})
srv = make_server("127.0.0.1", 5099, app); threading.Thread(target=srv.serve_forever, daemon=True).start()
errors=[]; dialogs=[]
with sync_playwright() as p:
    b = p.chromium.launch(); pg = b.new_page(viewport={"width":1200,"height":900})
    pg.on("pageerror", lambda e: errors.append(str(e)))
    pg.on("console", lambda m: errors.append(m.text) if m.type=="error" else None)
    pg.on("dialog", lambda dlg: (dialogs.append(dlg.message), dlg.dismiss()))   # any alert() from XSS would land here
    pg.goto("http://127.0.0.1:5099/"); pg.wait_for_selector("#entries")

    # 1. live feedback + auto sensitivity
    pg.fill("#f-platform","Gmail"); pg.wait_for_timeout(700)
    print("auto sensitivity for Gmail:", pg.input_value("#f-sensitivity"))
    pg.fill("#f-password","Summer2024!"); pg.wait_for_selector("#f-live:not([hidden])")
    expect(pg.locator("#f-strength-text")).to_contain_text("/100")
    print("live:", pg.inner_text("#f-strength-text"), "|", pg.inner_text("#f-tips")[:120].replace("\n"," / "))

    # 2. generate
    pg.click("#gen-pw"); pg.wait_for_timeout(800)
    gen = pg.input_value("#f-password"); print("generated len", len(gen), "| msg:", pg.inner_text("#form-message")[:60])
    print("strength of generated:", pg.inner_text("#f-strength-text"))

    # 3. add Gmail with the Summer2024! password, then LinkedIn with Summer2023! (similar) and Instagram reusing
    def add(name, pw, sens=None):
        pg.fill("#f-platform", name); pg.fill("#f-password", pw)
        if sens: pg.select_option("#f-sensitivity", sens)
        pg.click("button[type=submit]"); pg.wait_for_timeout(150); expect(pg.locator("#form-message")).not_to_have_text("Checking…")
        return pg.inner_text("#form-message")
    print(add("Gmail","Summer2024!","critical"))
    print(add("LinkedIn","Summer2023!"))
    print(add("Instagram","Summer2024!"))
    # 4. XSS payload as platform name
    print(add('<img src=x onerror=alert(1)>', "Summer2024!"))
    pg.wait_for_timeout(300)
    print("XSS dialogs fired:", dialogs, "| rows:", pg.locator("#entries tr").count(), "| alerts text has literal payload:", "<img" in pg.inner_text("#alerts"))

    # 5. update (rotate) Instagram
    pg.locator("#entries tr", has=pg.get_by_text("Instagram", exact=True)).get_by_text("Update").click()
    pg.fill("#e-password","qkT8#mZ2vLp9wR4x-unique"); expect(pg.locator("#e-strength-text")).to_contain_text("/100")
    print("rotate live:", pg.inner_text("#e-strength-text"))
    pg.click("#edit-form button[type=submit]"); pg.wait_for_timeout(600)
    print("table msg:", pg.inner_text("#table-message"))
    # rotate to identical password -> error
    pg.locator("#entries tr", has=pg.get_by_text("Instagram", exact=True)).get_by_text("Update").click()
    pg.fill("#e-password","qkT8#mZ2vLp9wR4x-unique"); pg.click("#edit-form button[type=submit]"); pg.wait_for_timeout(500)
    print("identical rotate ->", pg.inner_text("#e-message")); pg.click("#e-cancel")

    # 6. import CSV
    csvp = d+"/export.csv"
    open(csvp,"w",encoding="utf-8").write("name,url,username,password\nGitHub,https://github.com/login,me,Summer2024!\nnews.example.com,https://www.news.example.com,me,k7Qz!p9Lm2#x\n,,,\nbad,,me,\n")
    pg.set_input_files("#import-file", csvp); pg.click("#import-form button"); expect(pg.locator("#tools-message")).to_contain_text("Imported", timeout=15000)
    print("import:", pg.inner_text("#tools-message")[:140])

    # 7. filter + delete confirm
    pg.fill("#q","github"); print("filtered rows:", pg.locator("#entries tr").count()); pg.fill("#q","")
    pg.locator("#entries tr", has=pg.get_by_text("news.example.com", exact=True)).get_by_text("Delete").click(); pg.click("#c-ok"); pg.wait_for_timeout(500)
    print("after delete:", pg.inner_text("#table-message"))

    # 8. erase all requires typing ERASE
    pg.click("#erase-all"); pg.click("#c-ok"); pg.wait_for_timeout(300)
    print("erase w/o typing -> still", pg.locator("#entries tr").count(), "rows (dialog open:", pg.locator("#confirm-dialog[open]").count(), ")")
    pg.fill("#c-type","ERASE"); pg.click("#c-ok"); expect(pg.locator("#tools-message")).to_contain_text("Erased")
    print("erase:", pg.inner_text("#tools-message"), "| rows:", pg.inner_text("#entries"))
    b.close()
print("errors:", errors); srv.shutdown()
