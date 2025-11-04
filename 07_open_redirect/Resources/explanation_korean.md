# 취약점 #7: 소셜 미디어 아이콘을 통한 Open Redirect (개방 리다이렉트)

## 🎯 취약점 유형
**Open Redirect - 검증되지 않은 리다이렉트**
- **OWASP 분류**: A01:2021 - Broken Access Control (접근 제어 취약점)
- **CWE 분류**: CWE-601 - URL Redirection to Untrusted Site (신뢰할 수 없는 사이트로의 URL 리다이렉트)

---

## 🔍 취약점 발견 과정

### 발견: 푸터의 소셜 미디어 아이콘
**위치**: 홈페이지 하단 푸터의 소셜 미디어 아이콘

웹사이트 푸터에 리다이렉트 메커니즘을 사용하는 소셜 미디어 아이콘이 있습니다:

![푸터의 소셜 미디어 아이콘](images/01-social-icons.png)

### 1단계: 리다이렉트 메커니즘 분석

**HTML 구조**:
```html
<ul class="icons">
    <li><a href="index.php?page=redirect&site=facebook" class="icon fa-facebook"></a></li>
    <li><a href="index.php?page=redirect&site=twitter" class="icon fa-twitter"></a></li>
    <li><a href="index.php?page=redirect&site=instagram" class="icon fa-instagram"></a></li>
</ul>
```

**핵심 관찰**: 링크가 소셜 미디어 사이트로 직접 가지 않고, `site` 파라미터가 있는 내부 리다이렉트 페이지를 사용합니다.

**왜 이게 문제일까?**
- 직접 링크보다 복잡함
- 사용자 입력(`site` 파라미터)을 신뢰함
- 추가적인 공격 표면 생성

### 2단계: 정상 리다이렉트 테스트

**테스트 1** - Facebook 리다이렉트:
```bash
curl -I "http://192.168.64.2/index.php?page=redirect&site=facebook"
```

**응답**:
```
HTTP/1.1 302 Moved Temporarily
Location: http://facebook.com/42Born2Code/
```

**테스트 2** - Twitter 리다이렉트:
```bash
curl -I "http://192.168.64.2/index.php?page=redirect&site=twitter"
```

**응답**:
```
HTTP/1.1 302 Moved Temporarily
Location: https://twitter.com/42born2code
```

**테스트 3** - Instagram 리다이렉트:
```bash
curl -I "http://192.168.64.2/index.php?page=redirect&site=instagram"
```

**응답**:
```
HTTP/1.1 302 Moved Temporarily
Location: https://instagram.com/42born2code/
```

**결론**: 서버가 룩업 테이블을 사용하여 사이트 이름을 URL에 매핑합니다.

### 3단계: 파라미터 검증 테스트

**테스트 4** - 유효하지 않은 site 파라미터:
```bash
curl "http://192.168.64.2/index.php?page=redirect&site=invalid"
```

**결과**: ✅ **FLAG 획득!**

![유효하지 않은 파라미터로 flag 획득](images/02-flag-obtained.png)

**Flag**: `b9e775a0291fed784a2d9680fcfad7edd6b8cdf87648da647aaf4bba288bcab3`

### Flag를 트리거하는 이유

서버에 **불충분한 에러 처리**가 있습니다:
- 유효한 파라미터: facebook, twitter, instagram
- 유효하지 않은 파라미터: 에러/예외 발생
- 서버가 적절한 에러 처리 대신 flag를 노출

이것이 다음의 중요성을 보여줍니다:
1. 입력 검증
2. 적절한 에러 처리
3. 에러 메시지에 민감한 정보를 노출하지 않기

---

## 💥 공격 방법

### 방법 1: 직접 URL 접속

브라우저에서 다음 URL 중 하나를 방문:
```
http://192.168.64.2/index.php?page=redirect&site=invalid
http://192.168.64.2/index.php?page=redirect&site=test
http://192.168.64.2/index.php?page=redirect&site=xyz
```

### 방법 2: curl 명령어

```bash
curl "http://192.168.64.2/index.php?page=redirect&site=invalid" | grep -i "flag"
```

### 방법 3: 자동화 테스트

```bash
#!/bin/bash
# 다양한 유효하지 않은 입력 테스트
for site in invalid test xyz 123 admin evil.com; do
    echo "테스트 중: $site"
    curl -s "http://192.168.64.2/index.php?page=redirect&site=$site" | grep -i "flag"
done
```

---

## 🌐 Open Redirect란 무엇인가?

### 개념

**Open Redirect**는 웹 애플리케이션이 신뢰할 수 없는 입력을 받아들여, 해당 입력에 포함된 URL로 리다이렉트할 수 있게 하는 취약점입니다.

**기본 흐름**:
```
사용자 클릭: http://trusted.com/redirect?url=http://evil.com
    ↓
서버 리다이렉트: http://evil.com
    ↓
사용자는 trusted.com에 있다고 생각하지만 실제로는 evil.com
```

**왜 위험한가?**
- 사용자가 **신뢰하는 도메인**에서 시작
- 리다이렉트를 **눈치채지 못함**
- 악의적인 사이트가 **합법적으로 보임**

### 리다이렉트의 정당한 사용

**정당한 용도**:
1. **로그인 후 리다이렉트**: 로그인 페이지 → 원래 페이지
2. **외부 링크 경고**: "외부 사이트로 이동합니다" 확인
3. **URL 단축 서비스**: bit.ly, goo.gl 등
4. **Analytics 추적**: 클릭 수 세기 후 리다이렉트

**안전한 구현 조건**:
- ✅ 화이트리스트 검증
- ✅ 사용자 확인
- ✅ 도메인 제한
- ✅ 적절한 로깅

---

## 🎯 실제 공격 시나리오

### 시나리오 1: 피싱 공격

**공격자가 악의적인 링크 생성**:
```
http://192.168.64.2/index.php?page=redirect&site=http://fake-facebook.com/login
```

**공격 흐름**:
```
1. 공격자가 이메일 전송: "계정 확인이 필요합니다, 여기 클릭하세요"
2. 링크가 신뢰할 수 있는 사이트(192.168.64.2)로 가는 것처럼 보임
3. 사용자가 클릭, 도메인을 신뢰
4. 공격자의 피싱 사이트로 리다이렉트됨
5. 사용자가 가짜 사이트에 자격 증명 입력
6. 공격자가 자격 증명 탈취
```

**왜 성공하는가?**
- ✅ 링크가 신뢰할 수 있는 도메인으로 시작
- ✅ 사용자가 리다이렉트를 눈치채지 못함
- ✅ 가짜 사이트가 실제와 동일하게 보임
- ✅ URL 바에서 최종 도메인을 확인 안 함

**실제 사례**:
- **Google** (2012): 피싱에 사용된 Open Redirect
- **PayPal** (2015): 자격 증명 탈취
- **Apple iCloud** (2018): 피싱 캠페인

### 시나리오 2: OAuth/SAML 악용

**OAuth 정상 흐름**:
```
1. 사용자: "Facebook으로 로그인"
2. 앱: facebook.com/oauth?redirect_uri=http://app.com/callback 으로 리다이렉트
3. Facebook: 사용자 로그인
4. Facebook: 인증 토큰과 함께 redirect_uri로 리다이렉트
5. 앱: 토큰 검증 및 사용자 로그인
```

**공격**:
```
공격자가 조작: redirect_uri=http://evil.com/steal
Facebook이 인증 토큰과 함께 evil.com으로 리다이렉트
공격자가 OAuth 토큰 탈취
공격자가 피해자 계정에 접근
```

**영향**:
- 💀 완전한 계정 탈취
- 🔓 모든 연결된 서비스 접근
- 📧 개인 정보 유출

**실제 사례**:
- **Facebook OAuth** (2014): 리다이렉트 취약점
- **Microsoft Office 365** (2017): SAML 리다이렉트 악용

### 시나리오 3: JavaScript 프로토콜을 통한 XSS

**악의적인 URL**:
```
http://192.168.64.2/index.php?page=redirect&site=javascript:alert(document.cookie)
```

**만약 서버가 프로토콜을 검증하지 않으면**:
```
브라우저가 JavaScript 실행
쿠키 탈취, 세션 하이재킹 가능
```

**기타 위험한 프로토콜**:
```
data:text/html,<script>alert(1)</script>
vbscript:msgbox(1)
file:///etc/passwd
```

### 시나리오 4: 보안 필터 우회

**상황**: 회사 방화벽이 evil.com 차단

**공격**:
```
http://trusted-company-site.com/redirect?url=http://evil.com
```

**결과**:
- ✅ 방화벽이 trusted-company-site.com 허용
- ✅ 사용자가 신뢰할 수 있는 프록시를 통해 evil.com으로 리다이렉트
- ✅ 방화벽 우회 성공!

**추가 우회 시나리오**:
- 콘텐츠 필터 우회
- URL 블랙리스트 우회
- 참조자(Referer) 체크 우회
- CORS 정책 우회

---

## 🚨 보안 문제점

### 1. 입력 검증 없음

**문제**: `site` 파라미터가 검증 없이 모든 값을 받아들입니다.

**취약한 코드** (가상):
```php
$site = $_GET['site'];

$sites = [
    'facebook' => 'http://facebook.com/42Born2Code/',
    'twitter' => 'https://twitter.com/42born2code',
    'instagram' => 'https://instagram.com/42born2code/'
];

if (isset($sites[$site])) {
    header("Location: " . $sites[$site]);
} else {
    // 검증 없음 - 적절한 에러 대신 flag 표시
    echo "Flag: ...";
}
```

**누락된 것**:
- ❌ $site가 허용 목록에 있는지 확인 안 함
- ❌ 유효하지 않은 값에 대한 에러 처리 없음
- ❌ 에러 상태에서 민감한 정보 노출

### 2. 불충분한 에러 처리

**문제**: 적절한 에러 메시지 대신, 서버가 flag를 노출합니다.

**일어나야 할 일**:
```php
if (!isset($sites[$site])) {
    http_response_code(404);
    error_log("Invalid redirect attempt: " . $site);
    die("유효하지 않은 소셜 미디어 사이트");
}
```

**보안 원칙**:
- 🚫 에러 메시지에 민감한 정보 포함하지 말 것
- 📝 관리자용 로그는 상세하게
- 👤 사용자용 메시지는 일반적으로
- 🔒 스택 트레이스 노출하지 말 것

### 3. 화이트리스트 접근법 부족

**문제**: 코드가 화이트리스트를 엄격하게 시행하지 않습니다.

**현재 (취약)**:
```php
// 모든 것을 받아들이고, 목록에 있을 때만 검증
if (isset($sites[$site])) {
    redirect($sites[$site]);
} else {
    // 취약한 에러 처리
}
```

**보안 접근법**:
```php
// 화이트리스트에 없는 것은 모두 거부
$allowed = ['facebook', 'twitter', 'instagram'];

if (!in_array($site, $allowed, true)) {
    http_response_code(400);
    die("유효하지 않은 사이트 파라미터");
}

redirect($sites[$site]);
```

**화이트리스트 vs 블랙리스트**:

| 접근법 | 장점 | 단점 |
|--------|------|------|
| **화이트리스트** | 안전 보장, 새 공격 자동 차단 | 유연성 낮음 |
| **블랙리스트** | 유연함 | 새 공격에 취약, 우회 쉬움 |

**결론**: 항상 화이트리스트 사용! ✅

### 4. URL 조작 가능성

**이 경우 외부 URL이 작동하지 않더라도**, 코드 구조가 다음에 취약할 수 있음을 시사:

```php
// 잠재적으로 취약한 패턴
header("Location: " . $_GET['url']);
```

**가능한 공격**:
```
?url=http://evil.com          → 피싱
?url=javascript:alert(1)      → XSS
?url=//evil.com               → 프로토콜 상대 리다이렉트
?url=/\evil.com               → 백슬래시 우회
?url=@evil.com                → 사용자명 파싱 악용
?url=http://evil.com@trusted.com  → URL 파싱 혼란
```

---

## 🛡️ 완화 방법

### 1. 엄격한 화이트리스트 검증 구현

**보안 구현**:
```php
// 허용된 사이트 정의
$allowed_sites = ['facebook', 'twitter', 'instagram'];
$site_urls = [
    'facebook' => 'http://facebook.com/42Born2Code/',
    'twitter' => 'https://twitter.com/42born2code',
    'instagram' => 'https://instagram.com/42born2code/'
];

$site = $_GET['site'] ?? '';

// 화이트리스트 검증
if (!in_array($site, $allowed_sites, true)) {
    http_response_code(400);
    error_log("유효하지 않은 리다이렉트 시도: " . $site);
    die("유효하지 않은 소셜 미디어 사이트");
}

// 화이트리스트된 URL로 리다이렉트
header("Location: " . $site_urls[$site]);
exit();
```

**장점**:
- ✅ 미리 정의된 사이트만 허용
- ✅ 엄격한 비교 (`===`)
- ✅ 적절한 에러 처리
- ✅ 보안 모니터링을 위한 로깅

### 2. 사용자 제어 리다이렉트 피하기

**더 나은 접근법** - 직접 링크:
```html
<!-- ❌ 나쁨: 사용자 제어 리다이렉트 -->
<a href="index.php?page=redirect&site=facebook">Facebook</a>

<!-- ✅ 좋음: 직접 링크 -->
<a href="http://facebook.com/42Born2Code/"
   target="_blank"
   rel="noopener noreferrer">Facebook</a>
```

**장점**:
- 악용할 리다이렉트 메커니즘 없음
- 사용자에게 더 빠름 (추가 홉 없음)
- `rel="noopener noreferrer"`가 참조자 유출 방지

**rel 속성 설명**:
- `noopener`: 새 창이 `window.opener` 접근 못하게 함
- `noreferrer`: Referer 헤더 전송 안 함
- **보안**: 타겟 페이지가 원본 페이지 조작 못하게 방지

### 3. 리다이렉트 URL 검증

**리다이렉트가 필요한 경우**:
```php
function validateRedirectURL($url) {
    $parsed = parse_url($url);

    // 유효한 URL 구조여야 함
    if (!$parsed || !isset($parsed['host'])) {
        return false;
    }

    // 허용된 도메인 화이트리스트
    $allowed_domains = ['facebook.com', 'twitter.com', 'instagram.com'];

    if (!in_array($parsed['host'], $allowed_domains)) {
        return false;
    }

    // HTTP/HTTPS 프로토콜만 허용
    if (!in_array($parsed['scheme'], ['http', 'https'])) {
        return false;
    }

    // 경로 검증 (선택사항)
    if (isset($parsed['path']) && strpos($parsed['path'], '..') !== false) {
        return false;  // 경로 순회 방지
    }

    return true;
}

$redirect_url = $_GET['url'] ?? '';

if (!validateRedirectURL($redirect_url)) {
    http_response_code(400);
    die("유효하지 않은 리다이렉트 URL");
}

header("Location: " . $redirect_url);
exit();
```

**검증 체크리스트**:
- ✅ URL 구조 파싱
- ✅ 도메인 화이트리스트 확인
- ✅ 프로토콜 제한 (http/https만)
- ✅ 경로 순회 방지
- ✅ 사용자명/비밀번호 구성 요소 거부

### 4. 간접 참조 맵 사용

**보안 패턴**:
```php
// URL 대신 ID 사용
$redirect_id = $_GET['id'] ?? '';

$redirects = [
    '1' => 'http://facebook.com/42Born2Code/',
    '2' => 'https://twitter.com/42born2code',
    '3' => 'https://instagram.com/42born2code/'
];

if (!isset($redirects[$redirect_id])) {
    http_response_code(400);
    die("유효하지 않은 리다이렉트");
}

header("Location: " . $redirects[$redirect_id]);
exit();
```

**URL 형태**:
```
index.php?page=redirect&id=1
```

**장점**:
- 🔒 사용자가 임의 URL 지정 불가
- 🔒 악의적인 도메인 주입 불가
- ✅ 간단하고 안전함

### 5. 적절한 에러 처리 구현

**민감한 정보를 절대 노출하지 말 것**:
```php
// ❌ 나쁨
catch (Exception $e) {
    echo "Error: " . $e->getMessage();
    echo "Stack trace: " . $e->getTraceAsString();
    echo "Flag: " . $flag;  // 절대 하지 말 것!
}

// ✅ 좋음
catch (Exception $e) {
    // 관리자를 위한 로그
    error_log("Redirect error: " . $e->getMessage());
    error_log("Stack trace: " . $e->getTraceAsString());

    // 사용자를 위한 일반적인 메시지
    http_response_code(500);
    echo "오류가 발생했습니다. 나중에 다시 시도해주세요.";
}
```

**로깅 모범 사례**:
```php
// 상세한 서버 로그
error_log(sprintf(
    "Invalid redirect attempt - IP: %s, Site: %s, User-Agent: %s",
    $_SERVER['REMOTE_ADDR'],
    $_GET['site'] ?? 'none',
    $_SERVER['HTTP_USER_AGENT'] ?? 'unknown'
));
```

### 6. 외부 리다이렉트에 대한 사용자 확인 추가

**외부 리다이렉트가 필요한 경우**:
```html
<!DOCTYPE html>
<html>
<head>
    <title>사이트를 떠납니다</title>
</head>
<body>
    <h2>⚠️ 우리 사이트를 떠나고 있습니다</h2>
    <p>다음 사이트로 리다이렉트됩니다: <strong>facebook.com</strong></p>
    <p>계속하시겠습니까?</p>
    <div>
        <a href="http://facebook.com/42Born2Code/" class="btn-continue">
            ✅ 예, 계속
        </a>
        <a href="/" class="btn-back">
            ❌ 아니오, 돌아가기
        </a>
    </div>
    <p class="warning">
        외부 사이트의 콘텐츠에 대해 책임지지 않습니다.
    </p>
</body>
</html>
```

**추가 보안 기능**:
```php
// 5초 후 자동 리다이렉트
echo '<meta http-equiv="refresh" content="5;url=http://facebook.com/42Born2Code/">';
echo '<p>5초 후 자동으로 리다이렉트됩니다...</p>';
```

---

## 📊 영향 평가

### CVSS 3.1 점수: 6.1 (중간)

**공격 벡터**: 네트워크 (AV:N)
**공격 복잡성**: 낮음 (AC:L)
**필요한 권한**: 없음 (PR:N)
**사용자 상호작용**: 필요함 (UI:R) - 사용자가 악의적인 링크 클릭해야 함
**범위**: 변경됨 (S:C) - 다른 출처로 리다이렉트
**기밀성**: 낮음 (C:L) - 피싱으로 자격 증명 탈취 가능
**무결성**: 낮음 (I:L) - 사용자 인식 수정 가능
**가용성**: 없음 (A:N)

### 실제 영향

**성공적인 Open Redirect로 가능한 것**:
- 🎣 피싱 공격 (가장 흔함)
- 🔓 OAuth 토큰 탈취
- 🔄 세션 고정
- 🌐 SSRF (일부 경우)
- 🚫 URL 블랙리스트 우회
- 📊 참조자 체크 우회
- 🔍 SEO 조작

**실제 취약점 사례**:
- **Google** (2012): 피싱에 사용된 Open Redirect
- **Facebook** (2014): OAuth 리다이렉트 취약점
- **PayPal** (2015): 자격 증명 탈취
- **Microsoft** (2016-2020): 여러 Open Redirect 인스턴스
- **Apple iCloud** (2018): 피싱 캠페인

**통계**:
- 웹 애플리케이션의 **25%**에서 Open Redirect 발견 (HackerOne, 2022)
- 평균 버그바운티: $500-$2,000
- 피싱 캠페인의 **60%**에서 사용됨 (Verizon DBIR, 2023)
- 평균 발견 시간: 150일
- 평균 수정 시간: 30일

---

## 📚 참고자료

- [OWASP Unvalidated Redirects](https://cheatsheetseries.owasp.org/cheatsheets/Unvalidated_Redirects_and_Forwards_Cheat_Sheet.html)
- [CWE-601: URL Redirection to Untrusted Site](https://cwe.mitre.org/data/definitions/601.html)
- [OWASP Top 10 A01:2021](https://owasp.org/Top10/A01_2021-Broken_Access_Control/)
- [PortSwigger Open Redirection](https://portswigger.net/kb/issues/00500100_open-redirection-reflected)

## 🛠️ 사용된 도구

- **브라우저**: 수동 테스트
- **curl**: 커맨드라인 HTTP 테스트
- **DevTools**: 네트워크 탭 분석

---
**Flag**: `b9e775a0291fed784a2d9680fcfad7edd6b8cdf87648da647aaf4bba288bcab3`
