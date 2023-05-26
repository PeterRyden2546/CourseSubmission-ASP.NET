var lastnameInput = document.querySelector('[data-val="true"][type="lastname"][name="LastName"]');

lastnameInput.addEventListener("keyup", function (e) {
    lastnameValidator(e.target.value);

});

function lastnameValidator(value) {
    const lastNameRegEx = /^[a-öA-Ö]{2,}(?:[ é'-][a-öA-Ö]+)*$/;
    if (!lastNameRegEx.test(value))
        document.querySelector('[data-valmsg-for="LastName"]').innerHTML = "Last name is invalid"
    else
        document.querySelector('[data-valmsg-for="LastName"]').innerHTML = ""
}

