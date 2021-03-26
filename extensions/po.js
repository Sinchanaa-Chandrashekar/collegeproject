document.addEventListener('DOMContentLoaded', function() {
    var checkPageButton = document.getElementById('checkPage');
    checkPageButton.addEventListener('click', function() {
  
      chrome.tabs.getSelected(null, function(tab) {
        d = document;
  
        $.ajax({
          url: 'http://127.0.0.1:5000/',
          type: 'POST',
          data: {url: tab.url},
          success: function(data){
            let k = d.querySelector('.info');
            console.log(data)
            // k.innerText = data;
            alert(data);
            k.style.display = 'block';
            
          }
        })
      });
    }, false);
  }, false);