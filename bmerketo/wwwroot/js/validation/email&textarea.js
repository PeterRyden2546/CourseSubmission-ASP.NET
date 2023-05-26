var elements = document.querySelectorAll('[data-val="true"]');

for (let element of elements) {
    element.addEventListener("keyup", function (e) {
        switch (e.target.type) {
            case 'email':
                emailValidator(e.target.value);
                break;
            case 'textarea':
                textareaValidator(e.target.value);
                break;
        }
    });
}


function emailValidator(value) {
    const emailRegEx = /^[a-zA-Z0-9._%+-]+@[a-zA-Z0-9.-]+\.[a-zA-Z]{2,}$/;
    if (!emailRegEx.test(value))
        document.querySelector('[data-valmsg-for="Email"]').innerHTML = "Email is invalid"
    else
        document.querySelector('[data-valmsg-for="Email"]').innerHTML = ""
}

function textareaValidator(value) {
    const textareaRegEx = /^[\w\d\s!#$%&'*+\-./:;<=>?@,[\]^_`{|}~]{2,}$/;
    if (!textareaRegEx.test(value))
        document.querySelector('[data-valmsg-for="Message"]').innerHTML = "Message is too short"
    else
        document.querySelector('[data-valmsg-for="Message"]').innerHTML = ""
}




