"""CI-only browser privacy/interaction checks. Uses public test data, never real passwords."""
from functools import partial
from http.server import SimpleHTTPRequestHandler, ThreadingHTTPServer
from pathlib import Path
import re
import shutil
import tempfile
import threading
from urllib.parse import urlsplit
from playwright.sync_api import sync_playwright, expect

ROOT = Path(__file__).resolve().parents[1]
SUFFIX = '1E4C9B93F3F0682250B6CF8331B7EE68FD8'

class QuietHandler(SimpleHTTPRequestHandler):
    def log_message(self, *args):
        pass

def main():
    screenshots = ROOT / 'browser-checks'
    screenshots.mkdir(exist_ok=True)
    with tempfile.TemporaryDirectory() as temporary:
        shutil.copytree(ROOT / 'dist', Path(temporary) / 'example-tool')
        server = ThreadingHTTPServer(('127.0.0.1', 0), partial(QuietHandler, directory=temporary))
        threading.Thread(target=server.serve_forever, daemon=True).start()
        try:
            with sync_playwright() as p:
                browser = p.chromium.launch()
                context = browser.new_context(viewport={'width':1280,'height':1000})
                page = context.new_page()
                requests, errors = [], []
                page.on('request', lambda request: requests.append(request))
                page.on('pageerror', lambda error: errors.append(str(error)))
                response_mode = ['found']
                def provider(route):
                    request = route.request
                    assert request.url == 'https://api.pwnedpasswords.com/range/5BAA6'
                    assert request.method == 'GET'
                    assert request.headers.get('add-padding') == 'true'
                    assert not request.post_data
                    assert 'cookie' not in request.headers
                    assert 'referer' not in request.headers
                    body = f'{SUFFIX}:42\r\n' + 'A'*35 + ':1\r\n' + 'B'*35 + ':0\r\n'
                    if response_mode[0] == 'absent': body = 'A'*35 + ':1\r\n' + 'B'*35 + ':0\r\n'
                    if response_mode[0] == 'error': body = '<html>challenge</html>'
                    route.fulfill(status=200, content_type='text/plain', body=body, headers={'Access-Control-Allow-Origin':'*'})
                page.route('https://api.pwnedpasswords.com/range/*', provider)
                url = f'http://127.0.0.1:{server.server_port}/example-tool/'
                page.goto(url)
                expect(page.locator('#check')).to_be_enabled()
                page.locator('#password').fill('password') # Public HIBP documentation test vector.
                page.locator('#show-password').click()
                assert page.locator('#password').get_attribute('type') == 'text'
                page.locator('#show-password').click()
                assert not [r for r in requests if urlsplit(r.url).hostname != '127.0.0.1']
                page.locator('#check').click()
                expect(page.locator('#result-title')).to_have_text('Found in the breach dataset')
                assert page.locator('#password').input_value() == ''
                # text_content ignores the eyebrow's visual uppercase styling.
                expect(page.locator('#result-count')).to_have_text('42 recorded occurrences')
                outgoing = [r for r in requests if urlsplit(r.url).hostname != '127.0.0.1']
                assert len(outgoing) == 1
                assert all(re.fullmatch(r'https://api\.pwnedpasswords\.com/range/[A-F0-9]{5}',r.url) for r in outgoing)
                assert page.url == url
                assert page.evaluate('localStorage.length + sessionStorage.length') == 0
                assert not context.cookies()
                page.screenshot(path=str(screenshots/'desktop.png'),full_page=True)
                page.locator('#clear').click()
                assert page.locator('#password').input_value() == ''
                assert page.locator('#result').is_hidden()
                response_mode[0] = 'absent'
                page.locator('#password').fill('password')
                page.locator('#check').click()
                expect(page.locator('#result-title')).to_have_text('No match in this dataset')
                expect(page.locator('#result-detail')).to_contain_text('not proof that it is safe')
                response_mode[0] = 'error'
                page.locator('#password').fill('password')
                page.locator('#check').click()
                expect(page.locator('#status')).to_contain_text('unexpected response')
                assert page.locator('#result').is_hidden()
                page.locator('#clear').click()
                for width in (390, 360):
                    page.set_viewport_size({'width':width,'height':844})
                    assert page.evaluate('document.documentElement.scrollWidth <= window.innerWidth'), width
                page.set_viewport_size({'width':390,'height':844})
                page.screenshot(path=str(screenshots/'mobile.png'),full_page=True)
                assert not errors, errors
                browser.close()
            print('Browser checks passed: local assets, explicit padded range request, reset, errors and mobile layout')
        finally:
            server.shutdown()

if __name__ == '__main__':
    main()
