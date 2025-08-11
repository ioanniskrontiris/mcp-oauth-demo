// server/src/ticketsRepo.js
const TICKETS = [
  { id: "ev-1001", title: "Jazz Night", date: "2025-09-15", venue: "Blue Note", price: 42 },
  { id: "ev-1002", title: "Tech Conf Keynote", date: "2025-10-03", venue: "IETF Hall A", price: 0 },
  { id: "ev-1003", title: "Indie Film Premiere", date: "2025-11-20", venue: "Cinema X", price: 12 }
];

export function listTickets() {
  return TICKETS;
}

export function getTicket(id) {
  return TICKETS.find(t => t.id === id) || null;
}