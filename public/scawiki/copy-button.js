// Based on https://www.roboleary.net/2022/01/13/copy-code-to-clipboard-blog.html
document.addEventListener("DOMContentLoaded", function () {
	let blocks = document.querySelectorAll("pre[class^='language-']");

	blocks.forEach((block) => {
		if (navigator.clipboard) {
			// Code block header title
			let title = document.createElement("span");
			let lang = block.getAttribute("data-lang");
			title.innerHTML = lang;

			// Copy button icon
			let iconCopy = document.createElement("i");
			iconCopy.classList.add("ph-bold", "ph-copy");

			let iconCheck = document.createElement("i");
			iconCheck.classList.add("ph-bold", "ph-check-square-offset");

			// Copy button
			let button = document.createElement("button");
			let copyCodeText = document.getElementById("copy-code-text").textContent;
			button.setAttribute("title", copyCodeText);
			button.appendChild(iconCopy);
			button.appendChild(iconCheck);

			// Code block header
			let header = document.createElement("div");
			header.classList.add("header");

			if (block.classList.contains("z-code")) {
				header.classList.add("z-code");
			}

			header.appendChild(title);
			header.appendChild(button);

			// Container that holds header and the code block itself
			let container = document.createElement("div");
			container.classList.add("pre-container");
			container.appendChild(header);

			// Move code block into the container
			block.parentNode.insertBefore(container, block);
			container.appendChild(block);

			button.addEventListener("click", async () => {
				await copyCode(block, header, button);
			});
		}
	});

	async function copyCode(block, header, button) {
		let code = block.querySelector("code");
		let text = code.innerText;

		await navigator.clipboard.writeText(text);

		header.classList.add("active");
		button.setAttribute("disabled", true);

		header.addEventListener("animationend", () => {
			header.classList.remove("active");
			button.removeAttribute("disabled");
		}, { once: true });
	}
});
