/*!
 * Bootstrap v5.1.3 - Modal component (minimal version)
 */
(function (global, factory) {
  typeof exports === 'object' && typeof module !== 'undefined' ? module.exports = factory() :
  typeof define === 'function' && define.amd ? define(factory) :
  (global = typeof globalThis !== 'undefined' ? globalThis : global || self, global.bootstrap = factory());
})(this, (function () {
  'use strict';

  // Modal component
  class Modal {
    constructor(element, options = {}) {
      this._element = element;
      this._options = options;
      this._isShown = false;
      this._backdrop = null;
      this._focustrap = null;
      this._isTransitioning = false;
      this._scrollBar = null;
    }

    // Static
    static getInstance(element) {
      if (!element) return null;
      return element.modalInstance;
    }

    static getOrCreateInstance(element, config = {}) {
      let instance = this.getInstance(element);
      if (!instance) {
        instance = new this(element, config);
        element.modalInstance = instance;
      }
      return instance;
    }

    // Public
    toggle(relatedTarget) {
      return this._isShown ? this.hide() : this.show(relatedTarget);
    }

    show(relatedTarget) {
      if (this._isShown || this._isTransitioning) {
        return;
      }

      this._isShown = true;
      this._element.style.display = 'block';
      this._element.removeAttribute('aria-hidden');
      this._element.setAttribute('aria-modal', true);
      this._element.setAttribute('role', 'dialog');

      // Set backdrop
      document.body.classList.add('modal-open');
      const backdrop = document.createElement('div');
      backdrop.className = 'modal-backdrop fade show';
      document.body.appendChild(backdrop);
      this._backdrop = backdrop;

      // Make modal visible
      setTimeout(() => {
        this._element.classList.add('show');
      }, 10);
    }

    hide() {
      if (!this._isShown || this._isTransitioning) {
        return;
      }

      this._isShown = false;
      this._element.classList.remove('show');

      const complete = () => {
        this._element.style.display = 'none';
        this._element.setAttribute('aria-hidden', true);
        this._element.removeAttribute('aria-modal');
        this._element.removeAttribute('role');

        // Remove backdrop
        if (this._backdrop) {
          document.body.removeChild(this._backdrop);
          this._backdrop = null;
        }

        document.body.classList.remove('modal-open');
      };

      // Use timeout to mimic transition end
      setTimeout(complete, 300);
    }

    dispose() {
      if (this._backdrop) {
        document.body.removeChild(this._backdrop);
      }

      this._element.modalInstance = null;
      this._element = null;
      this._options = null;
      this._backdrop = null;
      this._isShown = null;
      this._isTransitioning = null;
    }
  }

  // Export
  return {
    Modal: Modal
  };
})); 