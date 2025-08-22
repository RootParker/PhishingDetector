document.addEventListener('DOMContentLoaded', () => {
    const cards = document.querySelectorAll('.card');
    cards.forEach(card => {
        card.addEventListener('mouseover', () => card.classList.add('shadow-lg'));
        card.addEventListener('mouseout', () => card.classList.remove('shadow-lg'));
    });
});
