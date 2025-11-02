const quotes = [
  "“Music gives a soul to the universe, wings to the mind, and life to everything.”",
  "“Game is not just a hobby, it’s a story you live in.”",
  "“Stay chill, stay real, stay creative.”",
  "“Silence isn’t empty, it’s full of answers.”",
  "“Be the player who never gives up.”"
];

document.getElementById('quoteBtn').addEventListener('click', () => {
  const quoteBox = document.getElementById('quoteBox');
  const random = Math.floor(Math.random() * quotes.length);
  quoteBox.textContent = quotes[random];
});