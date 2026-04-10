/* Online Voting System - Main JS */
document.addEventListener('DOMContentLoaded',function(){
    // Auto-dismiss alerts after 5 seconds
    const alerts=document.querySelectorAll('.alert');
    alerts.forEach(a=>{
        setTimeout(()=>{
            a.style.opacity='0';
            a.style.transform='translateY(-20px)';
            a.style.transition='all 0.3s';
            setTimeout(()=>a.remove(),300);
        },5000);
    });
    // Clear flash cookies
    document.cookie='flash_msg=;Path=/;Expires=Thu, 01 Jan 1970 00:00:01 GMT;';
    document.cookie='flash_type=;Path=/;Expires=Thu, 01 Jan 1970 00:00:01 GMT;';
    // Smooth scroll
    document.querySelectorAll('a[href^="#"]').forEach(anchor=>{
        anchor.addEventListener('click',function(e){
            const target=document.querySelector(this.getAttribute('href'));
            if(target){e.preventDefault();target.scrollIntoView({behavior:'smooth',block:'start'});}
        });
    });
    // Animate progress bars on results page
    if(document.querySelector('.progress-bar')){
        setTimeout(animateResults,500);
    }
    // Radio buttons visual enhancement
    document.querySelectorAll('input[type="radio"]').forEach(radio=>{
        radio.addEventListener('change',function(){
            const siblings=document.querySelectorAll('input[name="'+this.name+'"]');
            siblings.forEach(s=>{const p=s.closest('.candidate-card,.radio-option');if(p)p.classList.remove('selected');});
            const parent=this.closest('.candidate-card,.radio-option');
            if(parent)parent.classList.add('selected');
        });
    });
});

function animateResults(){
    document.querySelectorAll('.progress-bar').forEach(bar=>{
        const tw=parseFloat(bar.getAttribute('data-width'))||0;
        bar.style.width='0%';
        let w=0;
        const iv=setInterval(()=>{
            if(w>=tw)clearInterval(iv);
            else{w=Math.min(w+1,tw);bar.style.width=w+'%';}
        },10);
    });
}

function confirmVote(candidateName,candidateId,electionId){
    return confirm('Are you sure you want to vote for '+candidateName+'?\n\nThis action cannot be undone.');
}

function confirmDelete(name){
    return confirm('Are you sure you want to delete "'+name+'"?\n\nThis action cannot be undone.');
}
