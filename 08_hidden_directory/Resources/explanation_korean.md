# Breach #08: 숨겨진 디렉토리 노출

## 취약점 개요

**취약점 유형**: 정보 노출, 디렉토리 인덱싱
**위험도**: 중간
**공격 벡터**: 웹 크롤링, 강제 브라우징

웹사이트가 민감한 정보가 포함된 `/.hidden/` 디렉토리를 노출하고 있습니다. `robots.txt`에서 이 디렉토리 크롤링을 금지하고 있지만, 이는 보안 메커니즘이 아니며 쉽게 우회할 수 있습니다.

## 취약점 발견 과정

### 1단계: robots.txt 확인
**URL**: `http://192.168.64.2/robots.txt`

**내용**:
```
User-agent: *
Disallow: /whatever
Disallow: /.hidden
```

`robots.txt` 파일이 `/.hidden` 디렉토리의 존재를 드러내고 있습니다.

**핵심 포인트**: `robots.txt`는 웹 크롤러에 대한 권장사항일 뿐, 보안 제어가 아닙니다. 직접 접근을 막지 못합니다.

![robots.txt 내용](./images/01-robots-txt.png)

### 2단계: 숨겨진 디렉토리 접근
**URL**: `http://192.168.64.2/.hidden/`

디렉토리에 접근이 가능하며, 디렉토리 인덱싱이 활성화되어 있어 수많은 하위 디렉토리가 노출됩니다.

![.hidden 디렉토리 리스팅](./images/02-hidden-directory.png)

### 3단계: 재귀적 다운로드
`wget`을 사용하여 `.hidden` 디렉토리의 모든 파일을 재귀적으로 다운로드합니다:

```bash
wget --recursive --no-parent --execute robots=off http://192.168.64.2/.hidden/
```

**명령어 분석**:
- `--recursive`: 디렉토리 내용을 재귀적으로 다운로드
- `--no-parent`: 상위 디렉토리로 올라가지 않음
- `--execute robots=off`: robots.txt 제한 무시

### 4단계: 플래그 검색
다운로드된 디렉토리 구조에는 여러 `README` 파일이 포함되어 있습니다. finder 스크립트를 사용하여 플래그를 찾습니다:

```bash
./192.168.64.2/finder.sh | grep flag
```

**결과**:
```
Hey, here is your flag : d5eec3ec36cf80dce44a896f961c1831a05526ec215693c8f2c39543497d4466
```

![플래그 발견](./images/03-flag-found.png)

## 취약점 상세 설명

### 디렉토리 인덱싱이란?
디렉토리 인덱싱은 웹 서버가 인덱스 파일(`index.html` 등)이 없을 때 디렉토리의 내용을 나열하는 현상입니다. 이를 통해 사용자가 해당 디렉토리의 모든 파일을 탐색하고 접근할 수 있게 됩니다.

### robots.txt가 보안이 아닌 이유
`robots.txt`는 [로봇 배제 표준(Robots Exclusion Protocol)](https://ko.wikipedia.org/wiki/%EB%A1%9C%EB%B4%87_%EB%B0%B0%EC%A0%9C_%ED%91%9C%EC%A4%80)의 일부입니다:

**특징**:
- **목적**: 검색 엔진 크롤러에 대한 정중한 제안
- **강제성 없음**: 어떤 클라이언트든 무시할 수 있음
- **정보 누출**: 숨기고 싶은 위치를 오히려 공개
- **흔한 오해**: 접근 제어로 오인

**robots.txt의 역설**:
```
🤔 개발자: "/.hidden을 robots.txt에 추가해서 숨겨야지!"
😈 공격자: "오, robots.txt에 숨겨진 디렉토리 목록이 있네? 감사합니다!"
```

### 보안 문제점

#### 1. 정보 노출
- 민감한 파일이 누구에게나 접근 가능
- 백업 파일, 설정 파일, 임시 파일 등 노출 가능

#### 2. 디렉토리 탐색
- 전체 디렉토리 구조를 쉽게 탐색 가능
- 시스템 구조와 파일 조직 방식 파악

#### 3. 인증 부재
- "숨겨진" 콘텐츠에 대한 공개 접근
- 민감한 정보에 대한 접근 제어 없음

#### 4. robots.txt 역효과
- 숨기고 싶은 위치를 광고하는 효과
- 공격자에게 목표 제공

## 방어 방법

### 1. 디렉토리 인덱싱 비활성화

**Apache (.htaccess)**:
```apache
Options -Indexes
```

**Nginx (nginx.conf)**:
```nginx
autoindex off;
```

### 2. 적절한 접근 제어 구현

**Apache 기본 인증**:
```apache
<Directory "/var/www/html/.hidden">
    AuthType Basic
    AuthName "Restricted Area"
    AuthUserFile /etc/apache2/.htpasswd
    Require valid-user
</Directory>
```

**Nginx 기본 인증**:
```nginx
location /.hidden {
    auth_basic "Restricted Area";
    auth_basic_user_file /etc/nginx/.htpasswd;
}
```

### 3. robots.txt를 보안으로 사용하지 말 것

```
❌ 잘못된 접근:
   robots.txt로 민감한 디렉토리 "숨기기"
   → 정보 누출, 공격자에게 힌트 제공

✅ 올바른 접근:
   인증 및 권한 부여 메커니즘 사용
   → 실제 접근 제어, 보안 강화
```

### 4. 안전한 디렉토리 구조

**권장사항**:
- 민감한 파일은 웹 루트 외부에 저장
- 비공개 콘텐츠에 대한 적절한 인증 구현
- 화이트리스트 기반 접근 제어 사용
- 파일 권한 올바르게 설정

**디렉토리 구조 예시**:
```
/var/www/
├── html/              (웹 루트, 공개)
│   ├── index.html
│   └── public/
└── private/           (웹 루트 외부, 비공개)
    ├── config/
    ├── sensitive/
    └── .hidden/
```

### 5. 추가 보안 조치

**서버 설정**:
```apache
# 숨김 파일/디렉토리 접근 차단
<FilesMatch "^\.">
    Require all denied
</FilesMatch>
```

**파일 권한**:
```bash
# 웹 서버만 읽을 수 있도록 설정
chmod 600 sensitive_file.txt

# 디렉토리는 실행 권한 필요
chmod 700 /path/to/sensitive/directory
```

## 실제 사례와 영향

### 유사 취약점 사례
1. **백업 파일 노출**: `.bak`, `.old`, `~` 파일 노출로 소스 코드 유출
2. **Git 디렉토리 노출**: `/.git/` 접근으로 전체 소스 코드 복원 가능
3. **환경 설정 파일**: `.env`, `config.php` 등 민감 정보 포함 파일 노출

### 공격 시나리오
```
1. 공격자가 robots.txt 확인
   → /.hidden 디렉토리 발견

2. 디렉토리 인덱싱으로 파일 목록 확인
   → 민감한 README 파일들 발견

3. wget으로 전체 디렉토리 다운로드
   → 모든 파일 로컬에 복사

4. 스크립트로 자동화된 검색
   → 플래그 및 민감 정보 추출
```

## 참고 자료

- [OWASP - Forced Browsing](https://owasp.org/www-community/attacks/Forced_browsing)
- [CWE-548: Directory Indexing](https://cwe.mitre.org/data/definitions/548.html)
- [로봇 배제 표준 (Wikipedia)](https://ko.wikipedia.org/wiki/%EB%A1%9C%EB%B4%87_%EB%B0%B0%EC%A0%9C_%ED%91%9C%EC%A4%80)
- [OWASP - Information Disclosure](https://owasp.org/www-community/vulnerabilities/Information_exposure_through_directory_listing)

## 플래그

```
d5eec3ec36cf80dce44a896f961c1831a05526ec215693c8f2c39543497d4466
```
