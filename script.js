// 오늘 날짜를 표시하는 코드
const today = new Date();
document.getElementById('today').textContent = today.toLocaleDateString('ko-KR');

// 버튼 클릭 시 실행되는 함수
function showMessage() {
    const name = prompt('이름을 입력하세요:');
    if (name) {
        alert(name + '님, 웹 개발의 세계에 오신 것을 환영합니다! 🎉');
    }
}