from urllib.request import urlopen, build_opener
from urllib.parse import urlencode
from urllib.error import HTTPError
import exceptions


def test_index():
    assert 'WELCOME TO NTR PLUGIN DATABASE' in str(
        urlopen('http://127.0.0.1:8080/index').read(), 'utf-8').upper()


def test_addplgpg():
    url = 'http://127.0.0.1:8080/login'
    data = urlencode({'rtype': 'loginpg',
                      'email': 'test@test.test',
                      'pword': 'test'
                      }).encode('utf-8')
    content = urlopen(url=url, data=data)
    cookies = content.getheader('Set-Cookie')
    if 'AToken' not in cookies:
        raise exceptions.NoCookieReceived()
    else:
        opener = build_opener()
        opener.addheaders.append(('Cookie', cookies))
        opener.open('http://127.0.0.1:8080/additem')
        assert True


def test_editpg():
    url = 'http://127.0.0.1:8080/login'
    data = urlencode({'rtype': 'loginpg',
                      'email': 'test@test.test',
                      'pword': 'test'
                      }).encode('utf-8')
    content = urlopen(url=url, data=data)
    cookies = content.getheader('Set-Cookie')
    if 'AToken' not in cookies:
        raise exceptions.NoCookieReceived()
    else:
        opener = build_opener()
        opener.addheaders.append(('Cookie', cookies))
        opener.open('http://127.0.0.1:8080/edit')
        assert True


def test_logpg():
    urlopen('http://127.0.0.1:8080/login')
    assert True


def test_regpg():
    urlopen('http://127.0.0.1:8080/reg')
    assert True
