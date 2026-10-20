// evisReveal scrolls the raw BER pane so the 16-byte row holding byte off is
// centred. Only the pane scrolls, never the page, so the PDU tree stays put.
// Called from Datastar expressions (selection click, "Jump to selection").
window.evisReveal = (off) => {
  const body = document.getElementById('hexbody')
  if (!body || off < 0) return
  const row = body.querySelectorAll('.hrow')[Math.floor(off / 16)]
  if (!row) return
  body.scrollTo({ top: row.offsetTop - body.clientHeight / 2 + row.offsetHeight / 2, behavior: 'smooth' })
}
