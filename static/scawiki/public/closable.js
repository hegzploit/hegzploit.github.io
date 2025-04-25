const closable = document.querySelectorAll("details.closable");

closable.forEach((detail) => {
	detail.addEventListener("toggle", () => {
		if (detail.open) setTargetDetail(detail);
	});
});

function setTargetDetail(targetDetail) {
	closable.forEach((detail) => {
		if (detail !== targetDetail) {
			detail.open = false;
		}
	});
}

document.addEventListener("click", function (event) {
	const isClickInsideDetail = [...closable].some((detail) =>
		detail.contains(event.target)
	);

	if (!isClickInsideDetail) {
		closable.forEach((detail) => {
			detail.open = false;
		});
	}
});

const toggleNavbar = document.getElementById("toggle-navbar");
const siteNavbar = document.getElementById("site-navbar");
const mainContent = document.getElementById("main-content");

toggleNavbar.addEventListener("change", () => {
	if (toggleNavbar.checked) {
		toggleSidebar.checked = false;
	}
});

mainContent.addEventListener("click", () => {
	if (toggleNavbar.checked) toggleNavbar.checked = false;
});
