var cityInput = document.querySelector('[data-val="true"][type="city"][name="City"]');

cityInput.addEventListener("keyup", function (e) {
    cityValidator(e.target.value);

});

function cityValidator(value) {
    const cityRegEx = /^[\w\d\s!#$%&'*+\-./:;<=>?@[\]^_`{|}~]{2,}$/;
    if (!cityRegEx.test(value))
        document.querySelector('[data-valmsg-for="City"]').innerHTML = "City is invalid"
    else
        document.querySelector('[data-valmsg-for="City"]').innerHTML = ""
}
