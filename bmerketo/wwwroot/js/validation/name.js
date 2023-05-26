var nameInput = document.querySelector('[data-val="true"][type="name"][name="Name"]');

nameInput.addEventListener("keyup", function (e) {
    nameValidator(e.target.value);

});

function nameValidator(value) {
    const nameRegEx = /^[a-öA-Ö]{2,}(?:[ é'-][a-öA-Ö]+)*$/;
    if (!nameRegEx.test(value))
        document.querySelector('[data-valmsg-for="Name"]').innerHTML = "Name is invalid"
    else
        document.querySelector('[data-valmsg-for="Name"]').innerHTML = ""
}
