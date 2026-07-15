// Togo-Services — comportements front-end légers (aucune dépendance).

document.addEventListener("DOMContentLoaded", () => {
  // Rejoue les animations "reveal" uniquement lorsque l'élément entre
  // dans le viewport, pour un effet plus vivant sur les pages longues.
  const elements = document.querySelectorAll(".reveal");
  const observer = new IntersectionObserver(
    (entries) => {
      entries.forEach((entry) => {
        if (entry.isIntersecting) {
          entry.target.style.animationPlayState = "running";
          observer.unobserve(entry.target);
        }
      });
    },
    { threshold: 0.1 }
  );
  elements.forEach((el) => observer.observe(el));

  // Ferme automatiquement les messages flash après quelques secondes.
  document.querySelectorAll(".alerte-flash").forEach((alerte) => {
    setTimeout(() => {
      alerte.style.transition = "opacity .4s ease";
      alerte.style.opacity = "0";
      setTimeout(() => alerte.remove(), 400);
    }, 5000);
  });
});
