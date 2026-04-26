(function () {
  if (document.querySelector('script[type="application/ld+json"][data-ca9-schema]')) {
    return;
  }

  var schema = {
    "@context": "https://schema.org",
    "@graph": [
      {
        "@type": "WebSite",
        "@id": "https://duriantaco.github.io/ca9/#website",
        "name": "ca9",
        "url": "https://duriantaco.github.io/ca9/",
        "description": "Open source Python CVE reachability analysis documentation."
      },
      {
        "@type": "SoftwareApplication",
        "@id": "https://duriantaco.github.io/ca9/#software",
        "name": "ca9",
        "applicationCategory": "SecurityApplication",
        "operatingSystem": "Python 3.10+",
        "softwareVersion": "0.2.0",
        "description": "Open source Python CVE reachability analysis for reducing false-positive SCA alerts.",
        "url": "https://duriantaco.github.io/ca9/",
        "codeRepository": "https://github.com/duriantaco/ca9",
        "license": "https://mozilla.org/MPL/2.0/",
        "offers": {
          "@type": "Offer",
          "price": "0",
          "priceCurrency": "USD"
        }
      },
      {
        "@type": "SoftwareSourceCode",
        "@id": "https://github.com/duriantaco/ca9#source",
        "name": "ca9",
        "codeRepository": "https://github.com/duriantaco/ca9",
        "programmingLanguage": "Python",
        "runtimePlatform": "Python 3.10+",
        "license": "https://mozilla.org/MPL/2.0/"
      }
    ]
  };

  var script = document.createElement("script");
  script.type = "application/ld+json";
  script.setAttribute("data-ca9-schema", "true");
  script.text = JSON.stringify(schema);
  document.head.appendChild(script);
})();
