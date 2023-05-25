/* SPDX-FileCopyrightText: 2023 Greenbone AG
 *
 * SPDX-License-Identifier: GPL-2.0-or-later
 */

$(function () {
    var title = document.title.split(" - ")[1];

    var xpath = "//a[text()='" + title + "']";
    var matchingElement = document.evaluate(xpath, document, null, XPathResult.FIRST_ORDERED_NODE_TYPE, null).singleNodeValue;

    matchingElement.classList.add("selected");

    var navigator = document.getElementById("navigator");
    for (var element = matchingElement.parentElement; element != navigator; element = element.parentElement) {

        if (element.nodeName == "UL") {
            element.classList.add("active");
        }
    }
});
