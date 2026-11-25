document.addEventListener("DOMContentLoaded", () => {
  console.log("NEON PLAY запущен!");

  const heading = document.querySelector(".hero h2");

  if (heading) {
    heading.addEventListener("click", () => {
      heading.style.textShadow = "0 0 25px #00eaff";
    });
  }
});
