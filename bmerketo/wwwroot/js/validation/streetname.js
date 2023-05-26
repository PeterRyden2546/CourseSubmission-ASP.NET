var streetnameInput = document.querySelector('[data-val="true"][type="streetname"][name="StreetName"]');

streetnameInput.addEventListener("keyup", function (e) {
    streetnameValidator(e.target.value);

});

function streetnameValidator(value) {
    const streetNameRegEx = /^[a-zA-Z0-9\s!@#$%^&*()_+\-=[\]{};':"\\|,.<>\/?]{3,}$/;
    if (!streetNameRegEx.test(value))
        document.querySelector('[data-valmsg-for="StreetName"]').innerHTML = "Street name is invalid"
    else
        document.querySelector('[data-valmsg-for="StreetName"]').innerHTML = ""
}