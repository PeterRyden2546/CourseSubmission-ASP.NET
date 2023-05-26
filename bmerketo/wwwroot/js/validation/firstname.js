var firstnameInput = document.querySelector('[data-val="true"][type="firstname"][name="FirstName"]');

firstnameInput.addEventListener("keyup", function (e) {
    firstnameValidator(e.target.value);

});

function firstnameValidator(value) {
    const firstNameRegEx = /^[a-öA-Ö]{2,}(?:[ é'-][a-öA-Ö]+)*$/;
    if (!firstNameRegEx.test(value))
        document.querySelector('[data-valmsg-for="FirstName"]').innerHTML = "First name is invalid"
    else
        document.querySelector('[data-valmsg-for="FirstName"]').innerHTML = ""
}
