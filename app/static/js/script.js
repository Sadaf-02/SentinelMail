document.addEventListener('DOMContentLoaded', () => {
  const body = document.body;
  const navbar = document.querySelector('.navbar');
  const navLinks = Array.from(document.querySelectorAll('.navbar-nav .nav-link'));
  const mobileToggle = document.querySelector('.navbar-toggler');
  const navbarCollapse = document.querySelector('.navbar-collapse');
  const revealElements = document.querySelectorAll('.fade-in, .slide-up, .card-custom, .feature-item, .hero-content');
  const counters = document.querySelectorAll('[data-counter]');
  const buttons = document.querySelectorAll('.btn');
  const backToTopButton = document.createElement('button');

  backToTopButton.className = 'btn btn-accent back-to-top';
  backToTopButton.setAttribute('aria-label', 'Back to top');
  backToTopButton.innerHTML = '<i class="fa-solid fa-arrow-up"></i>';
  body.appendChild(backToTopButton);

  const setActiveLink = () => {
    const scrollPosition = window.scrollY + 120;

    navLinks.forEach((link) => {
      const targetId = link.getAttribute('href');
      if (!targetId || targetId.startsWith('#') === false) {
        return;
      }

      const section = document.querySelector(targetId);
      if (section && scrollPosition >= section.offsetTop && scrollPosition < section.offsetTop + section.offsetHeight) {
        navLinks.forEach((item) => item.classList.remove('active'));
        link.classList.add('active');
      }
    });
  };

  const handleNavbarScroll = () => {
    if (!navbar) return;

    if (window.scrollY > 20) {
      navbar.classList.add('scrolled');
    } else {
      navbar.classList.remove('scrolled');
    }
  };

  const toggleMobileMenu = () => {
    if (!mobileToggle || !navbarCollapse) return;

    mobileToggle.addEventListener('click', () => {
      navbarCollapse.classList.toggle('show');
    });
  };

  const smoothScroll = () => {
    document.querySelectorAll('a[href^="#"]').forEach((anchor) => {
      anchor.addEventListener('click', (event) => {
        const targetId = anchor.getAttribute('href');
        if (!targetId || targetId === '#') return;

        const target = document.querySelector(targetId);
        if (!target) return;

        event.preventDefault();
        target.scrollIntoView({ behavior: 'smooth', block: 'start' });
        if (navbarCollapse && navbarCollapse.classList.contains('show')) {
          navbarCollapse.classList.remove('show');
        }
      });
    });
  };

  const revealOnScroll = () => {
    const observer = new IntersectionObserver((entries) => {
      entries.forEach((entry) => {
        if (entry.isIntersecting) {
          entry.target.classList.add('visible');
          observer.unobserve(entry.target);
        }
      });
    }, { threshold: 0.15 });

    revealElements.forEach((element) => observer.observe(element));
  };

  const animateCounters = () => {
    counters.forEach((counter) => {
      const target = parseInt(counter.getAttribute('data-counter'), 10) || 0;
      const duration = 1400;
      const startTime = performance.now();

      const tick = (now) => {
        const progress = Math.min((now - startTime) / duration, 1);
        const value = Math.floor(progress * target);
        counter.textContent = value.toLocaleString();

        if (progress < 1) {
          requestAnimationFrame(tick);
        } else {
          counter.textContent = target.toLocaleString();
        }
      };

      const counterObserver = new IntersectionObserver((entries, observerInstance) => {
        entries.forEach((entry) => {
          if (entry.isIntersecting) {
            requestAnimationFrame(tick);
            observerInstance.disconnect();
          }
        });
      }, { threshold: 0.6 });

      counterObserver.observe(counter);
    });
  };

  const applyButtonRipple = () => {
    buttons.forEach((button) => {
      button.addEventListener('click', (event) => {
        const ripple = document.createElement('span');
        ripple.className = 'ripple';
        const rect = button.getBoundingClientRect();
        const size = Math.max(rect.width, rect.height);
        ripple.style.width = ripple.style.height = `${size}px`;
        ripple.style.left = `${event.clientX - rect.left}px`;
        ripple.style.top = `${event.clientY - rect.top}px`;
        button.appendChild(ripple);

        setTimeout(() => ripple.remove(), 550);
      });
    });
  };

  const handleBackToTop = () => {
    const showButton = () => {
      if (window.scrollY > 500) {
        backToTopButton.classList.add('show');
      } else {
        backToTopButton.classList.remove('show');
      }
    };

    backToTopButton.addEventListener('click', () => {
      window.scrollTo({ top: 0, behavior: 'smooth' });
    });

    window.addEventListener('scroll', showButton);
    showButton();
  };

  const addCardHover = () => {
    document.querySelectorAll('.card-custom, .card, .glass-card, .feature-item').forEach((card) => {
      card.addEventListener('mouseenter', () => card.classList.add('is-hovered'));
      card.addEventListener('mouseleave', () => card.classList.remove('is-hovered'));
    });
  };

  const init = () => {
    handleNavbarScroll();
    setActiveLink();
    toggleMobileMenu();
    smoothScroll();
    revealOnScroll();
    animateCounters();
    applyButtonRipple();
    handleBackToTop();
    addCardHover();
  };

  window.addEventListener('scroll', () => {
    handleNavbarScroll();
    setActiveLink();
  });

  init();
});
const observer = new IntersectionObserver(entries => {

entries.forEach(entry=>{

if(entry.isIntersecting){

entry.target.classList.add("show");

}

});

});

document.querySelectorAll(".fade-in,.slide-up").forEach(el=>{

observer.observe(el);

});