jQuery(document).ready(function($) {
	
	$(".action-remove").click(function (e) {
		if (!confirm("Are you sure you want to permanently remove this item?")) {
			e.stopPropagation();
			e.preventDefault();
		}
	});
	
    $(".clickable-row").click(function() {
        window.document.location = $(this).data("href");
    });
    
});