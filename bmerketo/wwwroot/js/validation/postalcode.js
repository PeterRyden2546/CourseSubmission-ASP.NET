var postalcodeInput = document.querySelector('[data-val="true"][type="postalcode"][name="PostalCode"]');

postalcodeInput.addEventListener("keyup", function (e) {
    postalcodeValidator(e.target.value);

});

function postalcodeValidator(value) {
    const postalCodeRegEx = /^(?=.*\d)\d{3}(?:\s?\d{2})?$/;
    if (!postalCodeRegEx.test(value))
        document.querySelector('[data-valmsg-for="PostalCode"]').innerHTML = "Postal code is invalid"
    else
        document.querySelector('[data-valmsg-for="PostalCode"]').innerHTML = ""
}
