var passwordInput = document.querySelector('[data-val="true"][type="password"][name="Password"]');
var confirmPasswordInput = document.querySelector('[data-val="true"][type="password"][name="ConfirmPassword"]');

passwordInput.addEventListener("keyup", function (e) {
    passwordValidator(e.target.value);
    if (confirmPasswordInput.value !== '' && e.target.value !== confirmPasswordInput.value) {
        document.querySelector('[data-valmsg-for="ConfirmPassword"]').innerHTML = "Passwords do not match";
    } else {
        document.querySelector('[data-valmsg-for="ConfirmPassword"]').innerHTML = "";
    }
});

confirmPasswordInput.addEventListener("keyup", function (e) {
    if (passwordInput.value !== '' && e.target.value !== passwordInput.value) {
        document.querySelector('[data-valmsg-for="ConfirmPassword"]').innerHTML = "Passwords do not match";
    } else {
        document.querySelector('[data-valmsg-for="ConfirmPassword"]').innerHTML = "";
    }
});

function passwordValidator(value) {
    const passwordRegEx = /^(?=.*[a-z])(?=.*[A-Z])(?=.*\d)(?=.*[!@#$%^&*])[a-zA-Z\d!@#$%^&*]{8,}$/;
    if (!passwordRegEx.test(value))
        document.querySelector('[data-valmsg-for="Password"]').innerHTML = "Password is invalid"
    else
        document.querySelector('[data-valmsg-for="Password"]').innerHTML = ""
}

function confirmPasswordValidator(value) {
    if (passwordInput.value !== '' && value !== passwordInput.value)
        document.querySelector('[data-valmsg-for="ConfirmPassword"]').innerHTML = "Passwords do not match";
    else
        document.querySelector('[data-valmsg-for="ConfirmPassword"]').innerHTML = "";
}