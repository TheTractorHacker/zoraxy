/*
    Dark Theme Toggle Manager

    This script is used to manage the dark theme toggle button in the header of the website.
    It will change the theme of the website to dark mode when the toggle is clicked and back to light mode when clicked again.

    Must be included just after the start of body tag in the HTML file.
*/

//The top bar (script/topbar.js) listens to this to show the current mode
function _themeChanged(){
    try { document.dispatchEvent(new CustomEvent("zoraxy:theme")); } catch (e) {}
}

function _whiteThemeHandleApplyChange(){
    $(".menubar .logo").attr("src", "img/logo.svg");
}

function _darkThemeHandleApplyChange(){
    $(".menubar .logo").attr("src", "img/logo_white.svg");
}


 //Check if the theme is dark, must be done before the body is loaded to prevent flickering
 function setDarkTheme(isDarkTheme = false){
    if (isDarkTheme){
        $("body").addClass("darkTheme");
        localStorage.setItem("theme", "dark");
        _themeChanged();

        //Check if the page is still loading, if not change the logo
        if (document.readyState == "complete"){
            _darkThemeHandleApplyChange();
        }else{
            //Wait for the page to load and then change the logo
            $(document).ready(function(){
                _darkThemeHandleApplyChange();
            });
        }
    }else{
        $("body").removeClass("darkTheme")
        localStorage.setItem("theme", "light");
        _themeChanged();
        //By default the page is white theme. So no need to change the logo if page is still loading
        if (document.readyState == "complete"){
            //Switching back to light theme
            _whiteThemeHandleApplyChange();
        }
    }
}

//No stored choice yet: follow the operating system preference ("auto") until the user picks a theme
function _systemPrefersDark(){
    try {
        return window.matchMedia && window.matchMedia("(prefers-color-scheme: dark)").matches;
    } catch (e) {
        return false;
    }
}

var _storedTheme = null;
try { _storedTheme = localStorage.getItem("theme"); } catch (e) {}
if (_storedTheme == "dark"){
    setDarkTheme(true);
}else if (_storedTheme == null && _systemPrefersDark()){
    setDarkTheme(true);
    try { localStorage.removeItem("theme"); } catch (e) {} //keep "auto" until the user toggles
}else{
    setDarkTheme(false);
    if (_storedTheme == null){
        try { localStorage.removeItem("theme"); } catch (e) {}
    }
}