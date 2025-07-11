console.log("Script is running"); // Add this line at the beginning of your script

// Add hovered class to selected list item
let list = document.querySelectorAll(".navigation li");

function activeLink() {
    console.log("Mouseover event triggered");
    list.forEach((item) => {
        item.classList.remove("hovered");
    });
    this.classList.add("hovered");
}

list.forEach((item) => item.addEventListener("mouseover", activeLink));

// Menu Toggle
let toggle = document.querySelector(".toggle");
let navigation = document.querySelector(".navigation");
let main = document.querySelector(".main");

console.log("Toggle element:", toggle);
console.log("Navigation element:", navigation);
console.log("Main element:", main);

toggle.addEventListener("click", function() {
    console.log("Toggle clicked");
    navigation.classList.toggle("active");
    main.classList.toggle("active");
});
