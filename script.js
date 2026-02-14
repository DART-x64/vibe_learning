// 오늘 날짜를 표시하는 코드
const today = new Date();
document.getElementById('today').textContent = today.toLocaleDateString('ko-KR');

// 버튼 클릭 시 실행되는 함수
function showMessage() {
    const name = prompt('이름을 입력하세요:');
    if (name) {
        alert(name + '님, 웹앱 개발의 세계에 오신 것을 환영합니다! 🎉');
    }
} 
// 자바는 주석 다는 법이 좀 다르네. 끝날 때는 //가 필요없나봄.
// 역시 ctrl+/ 단축키는 잘 먹네.
// 하나하나 코딩하려니 느리고 오타 수정 등 효율이 많이 떨어짐

