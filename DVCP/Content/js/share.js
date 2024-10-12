baseurl = "https://www.facebook.com/sharer/sharer.php?u=";
function buildFbURL(item) {
    item.href = baseurl + window.location.href;
    return true;
}
