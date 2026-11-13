"""Bounded OCR/QR extraction. Does not follow or request extracted URLs."""
import io
import shutil
import subprocess
import warnings
from dataclasses import dataclass
from functools import lru_cache

from PIL import Image, ImageOps, UnidentifiedImageError
import pytesseract
import zxingcpp

Image.MAX_IMAGE_PIXELS = 8_000_000


@dataclass
class ImageResult:
    text: str = ''
    qr: tuple = ()
    warning: str = ''


@lru_cache(maxsize=1)
def available_languages():
    if not shutil.which('tesseract'):
        return ()
    try:
        result = subprocess.run(['tesseract', '--list-langs'], capture_output=True,
                                text=True, timeout=3, check=True)
        return tuple(result.stdout.splitlines()[1:])
    except (OSError, subprocess.SubprocessError):
        return ()


def image_status(enabled, language):
    if not enabled:
        return 'OCR/QR 비활성화'
    available = available_languages()
    missing = [x for x in language.split('+') if x not in available]
    return (f'QR 활성 / OCR 설치 언어: {", ".join(available) or "없음"} / 요청 언어: {language}'
            + (f' / 누락 언어: {", ".join(missing)} (설치된 언어만 검사)' if missing else ''))


def inspect_image(data, language='eng+kor'):
    try:
        with warnings.catch_warnings():
            warnings.simplefilter('error', Image.DecompressionBombWarning)
            with Image.open(io.BytesIO(data)) as source:
                # First frame only; bounded pixels, dimensions and output.
                image = ImageOps.exif_transpose(source).convert('RGB')
                image.thumbnail((2000, 2000))
        qr = tuple(result.text[:2048] for result in zxingcpp.read_barcodes(image)[:8])
        available = available_languages()
        selected = [x for x in language.split('+') if x in available]
        missing = [x for x in language.split('+') if x not in available]
        if not selected:
            return ImageResult(qr=qr, warning='OCR 미검사: 요청한 tesseract 언어 미설치')
        try:
            text = pytesseract.image_to_string(image, lang='+'.join(selected), timeout=4,
                                               config='--psm 11')[:8000]
            return ImageResult(text, qr, 'OCR 일부 언어 미설치: ' + ', '.join(missing) if missing else '')
        except (RuntimeError, pytesseract.TesseractError):
            return ImageResult(qr=qr, warning='OCR 실패/시간 초과: 설치 언어와 시스템 확인')
    except (UnidentifiedImageError, OSError, ValueError, RuntimeError, Image.DecompressionBombError,
            Image.DecompressionBombWarning):
        return ImageResult(warning='이미지 디코딩 실패 또는 픽셀 제한 초과')
