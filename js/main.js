var loadTime, readyTime;

function reportTracking(category, action, label, value) {
    ga("send", "event", category, action, label, value);
}

function handleGoToLink(event) {
    event.preventDefault();

    var linkVal = $(this).attr('href'),
        linkName = $(this).data('linkname'),
        afterLoad = Math.round((new Date().getTime() - loadTime) / 1000),
        afterReady = Math.round((new Date().getTime() - readyTime) / 1000);

    reportTracking('Homepage', linkName, 'zalmos');
    reportTracking('Go to click', 'pTime after load', afterLoad, afterLoad);
    reportTracking('Go to click', 'pTime after ready', afterReady, afterReady);

    $('#appendedInputButton').val(linkVal);
    return $('#addressForm').submit();
}

function handleNewsletterSubscription(event) {
    event.preventDefault();

    $.ajax({
        url: '/ajax/newsletter',
        method: 'POST',
        data: {
            timestamp: new Date().getTime(),
            email: $(this).find('input[name=email]').val()
        },
        success: function(response) {
            var newsletterBox = $('#newsletterBox');

            if(response.status.code === 200) {
                newsletterBox.find('.alert-info').addClass('hidden');
                newsletterBox.find('.alert-success').removeClass('hidden');
            }
        },
        error: function(a,b,c) {

        }
    });
}

function handleShowMore() {
    var $this = $(this);

    reportTracking('Homepage', '+ More', 'zalmos');

    if ($this.hasClass('active')) {
        $this.removeClass('active');
    } else {
        $this.addClass('active');
    }
}

$(document).off('click', '.gotoLink a', handleGoToLink);
$(document).on('click', '.gotoLink a', handleGoToLink);

$(document).off('submit', '#subscribeForm', handleNewsletterSubscription);
$(document).on('submit', '#subscribeForm', handleNewsletterSubscription);

$(document).off('click', '.show-more', handleShowMore);
$(document).on('click', '.show-more', handleShowMore);

$(window).on('load', function() {
    $('p.gotoLink').removeClass('hide');
    loadTime = new Date().getTime();
});

$(document).on('ready', function() {
    readyTime = new Date().getTime();
});