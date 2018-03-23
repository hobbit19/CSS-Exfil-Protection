
// Only scan single stylesheet
function scan_css_single(css_stylesheet)
{
    // Create new filter sheet to ensure styles are overwritten
    filter_sheet = document.createElement('style');
    filter_sheet.className = "__css_exfil_protection_filtered_styles";
    filter_sheet.innerText = "";
    document.head.appendChild(filter_sheet);

    var selectors   = [];
    var selectorcss = [];
    var rules       = getCSSRules(css_stylesheet);
    console.log("New CSS Found:");
    //console.log(css_stylesheet);

    if(rules == null)
    {
        // Retrieve and parse cross-domain stylesheet
        console.log("Cross domain stylesheet: "+ css_stylesheet.href);
        incrementSanitize();
        getCrossDomainCSS(css_stylesheet);
    }
    else
    {
        incrementSanitize();
        handleImportedCSS(rules);

        // Parse same-origin stylesheet
        console.log("DOM stylesheet...");
        var _selectors = parseCSSRules(rules);
        var filter_retval = filter_css(_selectors[0], _selectors[1]);

        // nothing sanitized, OK to not scan again
        if(filter_retval == 0)
        {
            // record hashed stylesheet here
            set_seen_hash(css_stylesheet.sheet);
        }

        if(checkCSSDisabled(css_stylesheet))
        {
            enableCSS(css_stylesheet);
        }

        //decrementSanitize();
    }
}



// Scan all document stylesheets
function scan_css() 
{
	var sheets = document.styleSheets;
	var sheets_length = sheets.length;

    for (var i=0; i < sheets_length; i++) 
	{
	    var selectors   = [];
	    var selectorcss = [];
	    var rules       = getCSSRules(sheets[i]);

        console.log(sheets[i]);
        //console.log(sheets[i].sheet);

        if(rules == null)
        {
            // Retrieve and parse cross-domain stylesheet
            console.log("Cross domain stylesheet: "+ sheets[i].href);
            incrementSanitize();
            getCrossDomainCSS(sheets[i]);
        }
        else
        {
            incrementSanitize();
            handleImportedCSS(rules);

            // Parse same-origin stylesheet
            console.log("DOM stylesheet...");
            var _selectors = parseCSSRules(rules);

            var filter_retval = filter_css(_selectors[0], _selectors[1]);

            // nothing sanitized, OK to not scan again
            if(filter_retval == 0)
            {
                // record hashed stylesheet here
                set_seen_hash(sheets[i].sheet);
            }

            if(checkCSSDisabled(sheets[i]))
            {
                enableCSS(sheets[i]);
            }

            decrementSanitize();
        }
	}
}



function handleImportedCSS(rules)
{
    if(rules != null)
    {
        // Scan for imported stylesheets
        for(var r=0; r < rules.length; r++)
        {
            if( Object.prototype.toString.call(rules[r]) == "[object CSSImportRule]")
            {
                // Adding new sheet to list
                incrementSanitize();

                // Found an imported CSS Stylesheet
                console.log("Imported CSS...");

                var _rules = getCSSRules(rules[r].styleSheet);
                if(_rules == null)
                {
                    // Parse imported cross domain sheet
                    console.log("Imported Cross Domain CSS...");
                    getCrossDomainCSS(rules[r].styleSheet);
                }
                else
                {
                    // Parse imported DOM sheet
                    console.log("Imported DOM CSS...");
                    var _selectors = parseCSSRules(_rules);
                    var filter_retval = filter_css(_selectors[0], _selectors[1]);

                    // nothing sanitized, OK to not scan again
                    if(filter_retval == 0)
                    {
                        // record hashed stylesheet here
                        set_seen_hash(rules[r].styleSheet.sheet);
                    }

                    decrementSanitize();
                }
            }
            else
            {
                // imported rules must always come first so end the loop if we see a non-import rule
                r = rules.length;
            }
        }
    }
}




function getCSSRules(_sheet)
{
    var rules = null;

	try 
	{
        //Loading CSS
	    //console.log("Loading CSS...");
	    rules = _sheet.rules || _sheet.cssRules;
	} 
	catch(e) 
	{
	    if(e.name !== "SecurityError") 
	    {
            console.log("Error loading rules:");
            console.log(e);
	        //throw e;
	    }
	}

    return rules;
}


function parseCSSRules(rules)
{
	var selectors   = [];
	var selectorcss = [];

    if(rules != null)
    {
        // Loop through all selectors and determine if any are looking for the value attribute and calling a remote URL
        for (r=0; r < rules.length; r++) 
        {
            var selectorText = null;
            if(rules[r].selectorText != null)
            {
                selectorText = rules[r].selectorText.toLowerCase();
            }

            var cssText = null;
            if(rules[r].cssText != null)
            {
                cssText = rules[r].cssText.toLowerCase();
            }

            // If CSS selector is parsing text and is loading a remote resource add to our blocking queue
            // Flag rules that:
            // 1) Match a value attribute selector which appears to be parsing text 
            // 2) Calls a remote URL (https, http, //)
            // 3) The URL is not an xmlns property
            if( 
                ( (selectorText != null) && (cssText != null) && 
                  (selectorText.indexOf('value') !== -1) && (selectorText.indexOf('=') !== -1) ) &&
                ( (cssText.indexOf('url') !== -1) && 
                    ( (cssText.indexOf('https://') !== -1) || (cssText.indexOf('http://') !== -1) || (cssText.indexOf('//') !== -1) ) && 
                    (cssText.indexOf("xmlns='http://") === -1) 
                )
              )
            {
                //CSS Exfil Protection blocked
                selectors.push(rules[r].selectorText);
                selectorcss.push(cssText);
            }

        }

    }

    // Check if any bad rules were found
    // if yes, temporarily disable stylesheet
    if (selectors[0] != null) 
    {
        //console.log("Found potentially malicious selectors!");
        if(rules[0] != null)
        {
            disableCSS(rules[0].parentStyleSheet);
        }
    }
    

    return [selectors,selectorcss];
}




function getCrossDomainCSS(orig_sheet)
{
    // This may occur if an injected link stylesheet doesn't exist
    if(orig_sheet == null)
    {
        decrementSanitize();
        return;
    }

	var rules;
    var url = orig_sheet.href;

    if(url != null)
    {
        if( seen_url.indexOf(url) === -1 )
        {
            seen_url.push(url);
        }
        else
        {
            //console.log("Already checked URL");
            decrementSanitize();
            return;
        }
    }

    var xhr = new XMLHttpRequest();
    xhr.open("GET", url, true);
    xhr.onreadystatechange = function() 
    {
        if (xhr.readyState == 4) 
        {
            // Create stylesheet from remote CSS
            var sheet = document.createElement('style');
            sheet.innerText = xhr.responseText;
            document.head.appendChild(sheet);
            
            // MG: this approach to retrieve the last inserted stylesheet sometimes fails, 
            // instead get the stylesheet directly from the temporary object (sheet.sheet)
            //var sheets = document.styleSheets;
            //rules = getCSSRules(sheets[ sheets.length - 1]);
            rules = getCSSRules(sheet.sheet);

            handleImportedCSS(rules);

            var _selectors = parseCSSRules(rules);
            var filter_retval = filter_css(_selectors[0], _selectors[1]);

            // nothing sanitized, OK to not scan again
            if(filter_retval == 0)
            {
                // record hashed stylesheet here
                set_seen_hash(sheet.sheet);
            }

            // Remove stylesheet
            sheet.disabled = true;
            sheet.parentNode.removeChild(sheet);

            
            if(checkCSSDisabled(orig_sheet))
            {
                enableCSS(orig_sheet);
            }

            decrementSanitize();
            
            return rules;
        }
    }
    xhr.send();
}



// Return 0 if nothing was sanitized, 1 otherwise
function filter_css(selectors, selectorcss)
{
    var retval = 0;

    // Loop through found selectors and modify CSS if necessary
    for(s in selectors)
    {
        if( selectorcss[s].indexOf('background') !== -1 )
        {
            filter_sheet.sheet.insertRule( selectors[s] +" { background-image:none !important; }", filter_sheet.sheet.cssRules.length);
            retval = 1;
        }
        if( selectorcss[s].indexOf('list-style') !== -1 )
        {
            filter_sheet.sheet.insertRule( selectors[s] +" { list-style: inherit !important; }", filter_sheet.sheet.cssRules.length);
            retval = 1;
        }
        if( selectorcss[s].indexOf('cursor') !== -1 )
        {
            filter_sheet.sheet.insertRule( selectors[s] +" { cursor: auto !important; }", filter_sheet.sheet.cssRules.length);
            retval = 1;
        }
        if( selectorcss[s].indexOf('content') !== -1 )
        {
            filter_sheet.sheet.insertRule( selectors[s] +" { content: normal !important; }", filter_sheet.sheet.cssRules.length);
            retval = 1;
        }

        // Causes performance issue if large amounts of resources are blocked, just use when debugging
        console.log("CSS Exfil Protection blocked: "+ selectors[s]);

        // Update background.js with bagde count
        block_count++;
    }
    chrome.extension.sendMessage(block_count.toString());

    return retval;
}



function disableCSS(_sheet)
{
    //console.log("Disabled CSS: "+ _sheet.href);
    _sheet.disabled = true;
}
function enableCSS(_sheet)
{
    //console.log("Enabled CSS: "+ _sheet.href);
    _sheet.disabled = false;
    
    // Some sites like news.google.com require a resize event to properly render all elements after re-enabling CSS
    window.dispatchEvent(new Event('resize'));
}
function checkCSSDisabled(_sheet)
{
    return _sheet.disabled;
}
function disableAndRemoveCSS(_sheet)
{
    _sheet.disabled = true;
    if(_sheet.parentNode != null)
    {
        _sheet.parentNode.removeChild(_sheet);
    }
}


function incrementSanitize()
{
    sanitize_inc++;
    //console.log("Increment: "+ sanitize_inc);
}
function decrementSanitize()
{
    sanitize_inc--;
    if(sanitize_inc <= 0)
    {
        disableAndRemoveCSS(css_load_blocker);
    }
    //console.log("Decrement: "+ sanitize_inc);
}

function buildContentLoadBlockerCSS()
{
    var csstext = "input,input ~ * { background-image:none !important; list-style: inherit !important; cursor: auto !important; content:normal !important; } input::before,input::after,input ~ *::before, input ~ *::after { content:normal !important; }";
    return csstext;
}

// https://www.amazon.ca/L-Surprise-Confetti-Pop-Collectible/dp/B079HM1VWD/ref=pd_rhf_dp_s_cp_0_3?_encoding=UTF8&pd_rd_i=B079HM1VWD&pd_rd_r=JWRAYJM1KPATNQ8XPNAB&pd_rd_w=1JHKy&pd_rd_wg=sxYz2&psc=1&refRID=JWRAYJM1KPATNQ8XPNAB


function set_seen_hash(sheet)
{
    return;
    console.log(sheet);
    var style_hash = btoa(sheet);
    console.log(style_hash);
    seen_hash[style_hash] = 1;
}



/*
 *  Initialize
 */

var filter_sheet      = null;   // Create stylesheet which will contain our override styles
var css_load_blocker  = null;   // Temporary stylesheet to prevent early loading of resources we may block
var sanitize_inc      = 0;      // Incrementer to keep track when it's safe to unload css_load_blocker
var block_count       = 0;      // Number of blocked CSSRules
var seen_url          = [];     // Keep track of scanned cross-domain URL's
var seen_hash         = {};


/*
// Create an observer instance to monitor CSS injection
var observer = new MutationObserver(function(mutations) {
    mutations.forEach(function(mutation) {



        if (
              ((mutation.addedNodes.length > 0) && (mutation.addedNodes[0].localName == "style")) ||
              ((mutation.addedNodes.length > 0) && (mutation.addedNodes[0].localName == "link")) ||
              (mutation.attributeName == "style") || 
              (mutation.attributeName == "link") 
           )
        {

            // Ensure we aren't re-scanning our injected stylesheet
            if(
                (mutation.addedNodes.length > 0) && 
                (mutation.addedNodes[0].classList.length > 0) && 
                (mutation.addedNodes[0].classList == "__css_exfil_protection_filtered_styles")
              )
            {
                // do nothing
                return;
            }


            //setTimeout(function observerScan() { 
                //console.log("async observer call...");
                    var skipscan = 0;
                    var style_hash = btoa(mutation.addedNodes[0]);

                    // check to see if we have already scanned this exact CSS
                    if(seen_hash[style_hash] != null)
                    {
                        skipscan = 1;
                    }
                    else
                    {
                        // Set this now for testing... need to only set this if the CSS has no sanitization
                        //console.log(style_hash);
                        //seen_hash[style_hash] = 1;
                    }

                    if(skipscan == 0)
                    {
                        if(mutation.addedNodes.length > 0)
                        {
                            if(mutation.addedNodes[0].sheet == null)
                            {
                                //console.log("Sheet not initialized yet...");
                                setTimeout(function checkSheetInit() { 
                                    //console.log("checking again...");
                                    
                                    if(mutation.addedNodes[0].sheet == null)
                                    {
                                        setTimeout(checkSheetInit, 10);
                                    }
                                    else
                                    {
                                        scan_css_single( mutation.addedNodes[0].sheet );
                                    }
                                }, 10);
                            }
                            else
                            {
                                scan_css_single( mutation.addedNodes[0].sheet );
                            }

                        }
                        else
                        {
                            // If we get here it means that it's due to an inline style which 
                            // isn't something that needs to be sanitized
                            //console.log(mutation);
                        }
                    }
            //}, 0);
        }
    });
});


// configuration of the observer:
var observer_config = { attributes: true, childList: true, subtree: true, characterData: true, attributeFilter: ["style","link"] };
*/




// Run as soon as the DOM has been loaded
window.addEventListener("DOMContentLoaded", function() {

    // Create temporary stylesheet that will block early loading of resources we may want to block
    css_load_blocker  = document.createElement('style');
    //css_load_blocker.innerText = buildContentLoadBlockerCSS();
    css_load_blocker.className = "__tmp_css_exfil_protection_load_blocker";
    document.head.appendChild(css_load_blocker);

    // Zero out badge
    chrome.extension.sendMessage(block_count.toString());

    chrome.storage.local.get({
        enable_plugin: 1
    }, function(items) {

	    if(items.enable_plugin == 1)
        {
            // Plugin enabled

            // Disable all CSS and Re-enable body (style set to none in plugin css-exfil.css)
            for (var i=0; i < document.styleSheets.length; i++) 
            {
                disableCSS(document.styleSheets[i]);
            }

            // Enable body -- use timeout to make call asynchronous
            setTimeout(function enableBody() { 
                document.getElementsByTagName("BODY")[0].style.display = "block";
            }, 0);


            // Create stylesheet that will contain our filtering CSS (if any is necessary)
            filter_sheet = document.createElement('style');
            filter_sheet.className = "__css_exfil_protection_filtered_styles";
            filter_sheet.innerText = "";
            document.head.appendChild(filter_sheet);

            // Disable CSS load blocker as soon as possible
            // Should provide better page rendering, but
            // still provide load blocking of potentially harmful resources
            //disableAndRemoveCSS(css_load_blocker);

            // Increment once before we scan, just in case decrement is called too quickly
            incrementSanitize();

            scan_css();

            // monitor document for delayed CSS injection
            //observer.observe(document, observer_config);
        }
        else
	    {
            //console.log("Disabling CSS Exfil Protection");
            css_load_blocker.disabled = true;

            // disable icon
            chrome.extension.sendMessage('disabled');
	    }
    });


}, false);



window.addEventListener("load", function() {

    chrome.storage.local.get({
        enable_plugin: 1
    }, function(items) {

	    if(items.enable_plugin == 1)
        {
            // Unload increment called before scan
            decrementSanitize();
        }
    });

}, false);




