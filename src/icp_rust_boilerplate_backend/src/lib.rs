// Import necessary dependencies
#[macro_use]
extern crate serde;
use candid::{Decode, Encode};
use ic_cdk::api::time;
use ic_stable_structures::memory_manager::{MemoryId, MemoryManager, VirtualMemory};
use ic_stable_structures::{BoundedStorable, Cell, DefaultMemoryImpl, StableBTreeMap, Storable};
use regex::Regex;
use std::{borrow::Cow, cell::RefCell};

// Use these types to store our canister's state and generate unique IDs
type Memory = VirtualMemory<DefaultMemoryImpl>;
type IdCell = Cell<u64, Memory>;

// Enumeration for event registration status
#[derive(
    candid::CandidType, Serialize, Deserialize, Clone, Copy, PartialEq, Eq, Hash, Default, Debug,
)]
enum RegistrationStatus {
    #[default]
    Registered,
    Attended,
    Missed,
}

// Define the Admin struct to represent administrator
#[derive(candid::CandidType, Clone, Serialize, Deserialize, Default)]
struct Admin {
    id: u64,
    name: String,
    email: String,
    password: String,
    created_at: u64,
}

impl Storable for Admin {
    fn to_bytes(&self) -> Cow<[u8]> {
        Cow::Owned(Encode!(self).unwrap())
    }

    fn from_bytes(bytes: Cow<[u8]>) -> Self {
        Decode!(bytes.as_ref(), Self).unwrap()
    }
}

impl BoundedStorable for Admin {
    const MAX_SIZE: u32 = 2048;
    const IS_FIXED_SIZE: bool = false;
}

// Define the event organizer struct to present event organizers
#[derive(candid::CandidType, Clone, Serialize, Deserialize, Default)]
struct EventOrganizer {
    id: u64,
    name: String,
    email: String,
    contact: String,
    created_at: u64,
}

impl Storable for EventOrganizer {
    fn to_bytes(&self) -> Cow<[u8]> {
        Cow::Owned(Encode!(self).unwrap())
    }

    fn from_bytes(bytes: Cow<[u8]>) -> Self {
        Decode!(bytes.as_ref(), Self).unwrap()
    }
}

impl BoundedStorable for EventOrganizer {
    const MAX_SIZE: u32 = 2048;
    const IS_FIXED_SIZE: bool = false;
}

// Define the Volunteer struct to represent volunteers
#[derive(candid::CandidType, Clone, Serialize, Deserialize, Default)]
struct Volunteer {
    id: u64,
    name: String,
    email: String,
    contact: String,
    skills: Vec<String>,
    created_at: u64,
}

impl Storable for Volunteer {
    fn to_bytes(&self) -> Cow<[u8]> {
        Cow::Owned(Encode!(self).unwrap())
    }

    fn from_bytes(bytes: Cow<[u8]>) -> Self {
        Decode!(bytes.as_ref(), Self).unwrap()
    }
}

impl BoundedStorable for Volunteer {
    const MAX_SIZE: u32 = 2048;
    const IS_FIXED_SIZE: bool = false;
}

// Define the Event struct to represent events
#[derive(candid::CandidType, Clone, Serialize, Deserialize, Default)]
struct Event {
    id: u64,
    title: String,
    description: String,
    date_time: u64,
    location: String,
    organizer_id: u64,
    created_at: u64,
}

impl Storable for Event {
    fn to_bytes(&self) -> Cow<[u8]> {
        Cow::Owned(Encode!(self).unwrap())
    }

    fn from_bytes(bytes: Cow<[u8]>) -> Self {
        Decode!(bytes.as_ref(), Self).unwrap()
    }
}

impl BoundedStorable for Event {
    const MAX_SIZE: u32 = 2048;
    const IS_FIXED_SIZE: bool = false;
}

// Define the Registration struct to represent event registrations
#[derive(candid::CandidType, Clone, Serialize, Deserialize, Default)]
struct Registration {
    id: u64,
    admin_id: u64,
    admin_password: String,
    event_id: u64,
    volunteer_id: u64,
    status: RegistrationStatus,
    registered_at: u64,
    attended_at: Option<u64>,
}

impl Storable for Registration {
    fn to_bytes(&self) -> Cow<[u8]> {
        Cow::Owned(Encode!(self).unwrap())
    }

    fn from_bytes(bytes: Cow<[u8]>) -> Self {
        Decode!(bytes.as_ref(), Self).unwrap()
    }
}

impl BoundedStorable for Registration {
    const MAX_SIZE: u32 = 2048;
    const IS_FIXED_SIZE: bool = false;
}

// Define the Feedback struct to represent feedback
#[derive(candid::CandidType, Clone, Serialize, Deserialize, Default)]
struct Feedback {
    id: u64,
    volunteer_id: u64,
    event_id: u64,
    feedback: String,
    rating: u8, // e.g., 1-5 stars
    created_at: u64,
}

impl Storable for Feedback {
    fn to_bytes(&self) -> Cow<[u8]> {
        Cow::Owned(Encode!(self).unwrap())
    }

    fn from_bytes(bytes: Cow<[u8]>) -> Self {
        Decode!(bytes.as_ref(), Self).unwrap()
    }
}

impl BoundedStorable for Feedback {
    const MAX_SIZE: u32 = 2048;
    const IS_FIXED_SIZE: bool = false;
}

// Define payloads

// Admin Payload
#[derive(candid::CandidType, Serialize, Deserialize)]
struct AdminPayload {
    name: String,
    email: String,
    password: String,
}

// EventOrganizer Payload
#[derive(candid::CandidType, Serialize, Deserialize)]
struct EventOrganizerPayload {
    name: String,
    email: String,
    contact: String,
}

// Volunteer Payload
#[derive(candid::CandidType, Serialize, Deserialize)]
struct VolunteerPayload {
    name: String,
    email: String,
    contact: String,
    skills: Vec<String>,
}

// Event Payload
#[derive(candid::CandidType, Serialize, Deserialize)]
struct EventPayload {
    title: String,
    description: String,
    date_time: u64,
    location: String,
    organizer_id: u64,
}

// Registration Payload
#[derive(candid::CandidType, Serialize, Deserialize)]
struct RegistrationPayload {
    admin_id: u64,
    admin_password: String,
    event_id: u64,
    volunteer_id: u64,
}

// Feedback Payload
#[derive(candid::CandidType, Serialize, Deserialize)]
struct FeedbackPayload {
    volunteer_id: u64,
    event_id: u64,
    feedback: String,
    rating: u8,
}

// Mark Registration as missed payload
#[derive(candid::CandidType, Serialize, Deserialize)]
struct MarkRegistrationAsMissedPayload {
    admin_id: u64,
    registration_id: u64,
    admin_password: String,
}

// Mark Registration as attended payload
#[derive(candid::CandidType, Serialize, Deserialize)]
struct MarkRegistrationAsAttendedPayload {
    admin_id: u64,
    registration_id: u64,
    admin_password: String,
}

// Thread-local variables that will hold our canister's state
thread_local! {
    static MEMORY_MANAGER: RefCell<MemoryManager<DefaultMemoryImpl>> = RefCell::new(
        MemoryManager::init(DefaultMemoryImpl::default())
    );

    static VOLUNTEERS_STORAGE: RefCell<StableBTreeMap<u64, Volunteer, Memory>> =
        RefCell::new(StableBTreeMap::init(
            MEMORY_MANAGER.with(|m| m.borrow().get(MemoryId::new(0)))
    ));

    static EVENTS_STORAGE: RefCell<StableBTreeMap<u64, Event, Memory>> =
        RefCell::new(StableBTreeMap::init(
            MEMORY_MANAGER.with(|m| m.borrow().get(MemoryId::new(1)))
    ));

    static REGISTRATIONS_STORAGE: RefCell<StableBTreeMap<u64, Registration, Memory>> =
        RefCell::new(StableBTreeMap::init(
            MEMORY_MANAGER.with(|m| m.borrow().get(MemoryId::new(2)))
    ));

    static FEEDBACKS_STORAGE: RefCell<StableBTreeMap<u64, Feedback, Memory>> =
        RefCell::new(StableBTreeMap::init(
            MEMORY_MANAGER.with(|m| m.borrow().get(MemoryId::new(3)))
    ));

    static ADMINS_STORAGE: RefCell<StableBTreeMap<u64, Admin, Memory>> =
        RefCell::new(StableBTreeMap::init(
            MEMORY_MANAGER.with(|m| m.borrow().get(MemoryId::new(4)))
    ));

    static EVENT_ORGANIZERS_STORAGE: RefCell<StableBTreeMap<u64, EventOrganizer, Memory>> =
        RefCell::new(StableBTreeMap::init(
            MEMORY_MANAGER.with(|m| m.borrow().get(MemoryId::new(5)))
    ));

    static ID_COUNTER: RefCell<IdCell> = RefCell::new(
        IdCell::init(MEMORY_MANAGER.with(|m| m.borrow().get(MemoryId::new(5))), 0)
            .expect("Cannot create a counter")
    );
}

// Helper function to generate a new unique ID
fn generate_id() -> u64 {
    ID_COUNTER.with(|counter| {
        let current_value = *counter.borrow().get();
        let _ = counter.borrow_mut().set(current_value + 1);
        current_value + 1
    })
}

// Helper function to get the current time in milliseconds since the Unix epoch
fn get_current_time() -> u64 {
    time() / 1_000_000 // Convert to milliseconds
}

// Function to create a new admin
#[ic_cdk::update]
fn create_admin(payload: AdminPayload) -> Result<Admin, String> {
    // Validate the payload to ensure all fields are provided
    if payload.name.is_empty() || payload.email.is_empty() || payload.password.is_empty() {
        return Err("Invalid input: Ensure 'name', 'email', and 'password' are provided and are of the correct types.".to_string());
    }

    // Validate the email address format
    let email_regex = Regex::new(r"^[^\s@]+@[^\s@]+\.[^\s@]+$").unwrap();
    if !email_regex.is_match(&payload.email) {
        return Err("Invalid input: Ensure 'email' is a valid email address.".to_string());
    }

    // Ensure each email is unique
    let existing_admins = ADMINS_STORAGE.with(|storage| {
        storage
            .borrow()
            .iter()
            .any(|(_, admin)| admin.email == payload.email)
    });
    if existing_admins {
        return Err("Invalid input: Admin with the same email already exists.".to_string());
    }

    // Ensure the password is strong enough
    if payload.password.len() < 8 {
        return Err("Invalid input: Ensure 'password' is at least 8 characters long.".to_string());
    }

    // Ensure the password is hashed before storing it

    // Create a new admin
    let admin = Admin {
        id: generate_id(),
        name: payload.name,
        email: payload.email,
        password: payload.password,
        created_at: get_current_time(),
    };

    ADMINS_STORAGE.with(|storage| storage.borrow_mut().insert(admin.id, admin.clone()));
    Ok(admin)
}

// Function to register an EventOrganizer
#[ic_cdk::update]
fn create_event_organizer(payload: EventOrganizerPayload) -> Result<EventOrganizer, String> {
    // Validate the payload to ensure all required fields are provided
    if payload.name.is_empty() || payload.email.is_empty() || payload.contact.is_empty() {
        return Err("Invalid input: Ensure 'name', 'email', and 'contact' are provided and are of the correct types.".to_string());
    }

    // Validate the email address format
    let email_regex = Regex::new(r"^[^\s@]+@[^\s@]+\.[^\s@]+$").unwrap();
    if !email_regex.is_match(&payload.email) {
        return Err("Invalid input: Ensure 'email' is a valid email address.".to_string());
    }

    // Ensure each email is unique
    let existing_event_organizers = EVENT_ORGANIZERS_STORAGE.with(|storage| {
        storage
            .borrow()
            .iter()
            .any(|(_, event_organizer)| event_organizer.email == payload.email)
    });
    if existing_event_organizers {
        return Err(
            "Invalid input: Event Organizer with the same email already exists.".to_string(),
        );
    }

    // Create a new event organizer
    let event_organizer = EventOrganizer {
        id: generate_id(),
        name: payload.name,
        email: payload.email,
        contact: payload.contact,
        created_at: get_current_time(),
    };

    EVENT_ORGANIZERS_STORAGE.with(|storage| {
        storage
            .borrow_mut()
            .insert(event_organizer.id, event_organizer.clone())
    });
    Ok(event_organizer)
}

// Function to create a new volunteer
#[ic_cdk::update]
fn create_volunteer(payload: VolunteerPayload) -> Result<Volunteer, String> {
    // Ensure all required fields are provided
    if payload.name.is_empty()
        || payload.email.is_empty()
        || payload.contact.is_empty()
        || payload.skills.is_empty()
    {
        return Err("Invalid input: Ensure 'name', 'contact', 'email', and 'skills' are provided and are of the correct types.".to_string());
    }

    // Validate the email address format
    let email_regex = Regex::new(r"^[^\s@]+@[^\s@]+\.[^\s@]+$").unwrap();
    if !email_regex.is_match(&payload.email) {
        return Err("Invalid input: Ensure 'email' is a valid email address.".to_string());
    }

    // Ensure each eamil is unique
    let existing_volunteers = VOLUNTEERS_STORAGE.with(|storage| {
        storage
            .borrow()
            .iter()
            .any(|(_, volunteer)| volunteer.email == payload.email)
    });
    if existing_volunteers {
        return Err("Invalid input: Volunteer with the same email already exists.".to_string());
    }

    // Create a new volunteer
    let volunteer = Volunteer {
        id: generate_id(),
        name: payload.name,
        email: payload.email,
        contact: payload.contact,
        skills: payload.skills,
        created_at: get_current_time(),
    };

    VOLUNTEERS_STORAGE.with(|storage| storage.borrow_mut().insert(volunteer.id, volunteer.clone()));
    Ok(volunteer)
}

// Function to retrieve a volunteer by ID
#[ic_cdk::query]
fn get_volunteer_by_id(volunteer_id: u64) -> Result<Volunteer, String> {
    let volunteer = VOLUNTEERS_STORAGE.with(|storage| storage.borrow().get(&volunteer_id));
    match volunteer {
        Some(volunteer) => Ok(volunteer),
        None => Err("Volunteer with the provided ID does not exist.".to_string()),
    }
}

// Function to retrieve volunteers in chunks (pagination)
#[ic_cdk::query]
fn get_volunteers_by_chunk(offset: u64, limit: u64) -> Result<Vec<Volunteer>, String> {
    // Ensure offset is not greater than the total number of volunteers
    let total_volunteers = VOLUNTEERS_STORAGE.with(|storage| storage.borrow().len() as u64);
    if offset >= total_volunteers {
        return Err(
            "Invalid input: Offset is greater than the total number of volunteers.".to_string(),
        );
    }

    // Ensure limit is not greater than the total number of volunteers
    let volunteers = VOLUNTEERS_STORAGE.with(|storage| {
        storage
            .borrow()
            .iter()
            .map(|(_, volunteer)| volunteer.clone())
            .collect::<Vec<Volunteer>>()
    });

    if volunteers.is_empty() {
        return Err("No volunteers found.".to_string());
    }

    let start = offset as usize;
    let end = (offset + limit) as usize;
    let volunteers_chunk = volunteers[start..end].to_vec();

    Ok(volunteers_chunk)
}

// Function to retrieve all volunteers
#[ic_cdk::query]
fn get_all_volunteers() -> Result<Vec<Volunteer>, String> {
    let volunteers = VOLUNTEERS_STORAGE.with(|storage| {
        storage
            .borrow()
            .iter()
            .map(|(_, volunteer)| volunteer.clone())
            .collect::<Vec<Volunteer>>()
    });

    if volunteers.is_empty() {
        return Err("No volunteers found.".to_string());
    }

    if volunteers.is_empty() {
        return Err("No volunteers found.".to_string());
    } else {
        Ok(volunteers)
    }
}

// Function to create a new event(Event is created by an EventOrganizer)
#[ic_cdk::update]
fn create_event(payload: EventPayload) -> Result<Event, String> {
    // Ensure all required fields are provided
    if payload.title.is_empty()
        || payload.description.is_empty()
        || payload.location.is_empty()
        || payload.organizer_id == 0
    {
        return Err("Invalid input: Ensure 'title', 'description', 'location', and 'organizer_id' are provided and are of the correct types.".to_string());
    }

    // Validate the organizer_id to ensure it exists
    let organizer =
        EVENT_ORGANIZERS_STORAGE.with(|storage| storage.borrow().get(&payload.organizer_id));
    match organizer {
        Some(_) => (),
        None => {
            return Err(
                "Invalid input: Event Organizer with the provided ID does not exist.".to_string(),
            )
        }
    }

    // Create a new event
    let event = Event {
        id: generate_id(),
        title: payload.title,
        description: payload.description,
        date_time: payload.date_time,
        location: payload.location,
        organizer_id: payload.organizer_id,
        created_at: get_current_time(),
    };

    EVENTS_STORAGE.with(|storage| storage.borrow_mut().insert(event.id, event.clone()));
    Ok(event)
}

// Helper Function to validate the admin password
fn validate_admin_password(admin_id: u64, admin_password: &str) -> Result<bool, String> {
    let admin = ADMINS_STORAGE.with(|storage| storage.borrow().get(&admin_id));
    match admin {
        Some(admin) => {
            if admin.password == admin_password {
                Ok(true)
            } else {
                Err(
                    "Invalid password: The provided password does not match the stored password."
                        .to_string(),
                )
            }
        }
        None => Err("Admin not found: The provided admin ID does not exist.".to_string()),
    }
}

// Function to retrieve all events
#[ic_cdk::query]
fn get_all_events() -> Result<Vec<Event>, String> {
    let events = EVENTS_STORAGE.with(|storage| {
        storage
            .borrow()
            .iter()
            .map(|(_, event)| event.clone())
            .collect::<Vec<Event>>()
    });

    // Return an error if no events are found
    if events.is_empty() {
        return Err("No events found.".to_string());
    } else {
        Ok(events)
    }
}

// Function to fetch an event by the event title
#[ic_cdk::query]
fn get_event_by_title(title: String) -> Result<Event, String> {
    let event = EVENTS_STORAGE.with(|storage| {
        storage
            .borrow()
            .iter()
            .find(|(_, event)| event.title == title)
            .map(|(_, event)| event.clone())
    });

    match event {
        Some(event) => Ok(event),
        None => Err("Event with the provided title does not exist.".to_string()),
    }
}

// Fetch event by Event Organizer's name
#[ic_cdk::query]
fn get_event_by_organizer_name(name: String) -> Result<Vec<Event>, String> {
    let events = EVENTS_STORAGE.with(|storage| {
        storage
            .borrow()
            .iter()
            .filter(|(_, event)| {
                let organizer = EVENT_ORGANIZERS_STORAGE.with(|storage| {
                    storage
                        .borrow()
                        .iter()
                        .find(|(_, organizer)| organizer.name == name)
                });
                match organizer {
                    Some(organizer) => event.organizer_id == organizer.0,
                    None => false,
                }
            })
            .map(|(_, event)| event.clone())
            .collect::<Vec<Event>>()
    });

    if events.is_empty() {
        return Err("No events found.".to_string());
    }

    Ok(events)
}

// Function to create a new registration for an event(volunteer registration done by the admin)
#[ic_cdk::update]
fn register_volunteers_for_events(payload: RegistrationPayload) -> Result<Registration, String> {
    // Ensure all required fields are provided
    if payload.admin_id == 0
        || payload.admin_password.is_empty()
        || payload.event_id == 0
        || payload.volunteer_id == 0
    {
        return Err("Invalid input: Ensure 'admin_id', 'admin_password', 'event_id', and 'volunteer_id' are provided and are of the correct types.".to_string());
    }

    // Validate the passed admin password to ensure it matches the stored admin password
    let is_valid_password = validate_admin_password(payload.admin_id, &payload.admin_password)?;
    if !is_valid_password {
        return Err(
            "Invalid password: The provided password does not match the stored password."
                .to_string(),
        );
    }

    // Validate the volunteer id to ensure it exists
    let volunteer = VOLUNTEERS_STORAGE.with(|storage| storage.borrow().get(&payload.volunteer_id));
    match volunteer {
        Some(_) => (),
        None => {
            return Err("Invalid input: Volunteer with the provided ID does not exist.".to_string())
        }
    }
    
    // Validate the event_id to ensure it exists
    let event = EVENTS_STORAGE.with(|storage| storage.borrow().get(&payload.event_id));
    match event {
        Some(_) => (),
        None => return Err("Invalid input: Event with the provided ID does not exist.".to_string()),
    }

    // Create a new registration and initialize the RegistrationStatus to Registered
    let registration = Registration {
        id: generate_id(),
        admin_id: payload.admin_id,
        admin_password: payload.admin_password,
        event_id: payload.event_id,
        volunteer_id: payload.volunteer_id,
        status: RegistrationStatus::Registered,
        registered_at: get_current_time(),
        attended_at: None,
    };

    REGISTRATIONS_STORAGE.with(|storage| {
        storage
            .borrow_mut()
            .insert(registration.id, registration.clone())
    });
    Ok(registration)
}

// Function to mark a registration as attended
#[ic_cdk::update]
fn mark_registration_as_attended(payload: MarkRegistrationAsAttendedPayload) -> Result<Registration, String> {
    // Ensure all required fields are provided
    if payload.admin_password.is_empty() {
        return Err("Invalid input: Ensure 'admin_id', 'admin_password', and 'registration_id' are provided and are of the correct types.".to_string());
    }

    // Validate the passed admin password to ensure it matches the stored admin password
    let registration = REGISTRATIONS_STORAGE.with(|storage| storage.borrow().get(&payload.registration_id));
    match registration {
        Some(registration) => {
            let is_valid_password =
                validate_admin_password(registration.admin_id, &payload.admin_password)?;
            if !is_valid_password {
                return Err(
                    "Invalid password: The provided password does not match the stored password."
                        .to_string(),
                );
            }
        }
        None => {
            return Err(
                "Invalid input: Registration with the provided ID does not exist.".to_string(),
            )
        }
    }

    // Update the registration status to Attended
    let registration = REGISTRATIONS_STORAGE.with(|storage| {
        let mut registration = storage.borrow().get(&payload.registration_id).unwrap().clone();
        registration.status = RegistrationStatus::Attended;
        registration.attended_at = Some(get_current_time());
        storage
            .borrow_mut()
            .insert(payload.registration_id, registration.clone());
        registration
    });

    Ok(registration)
}

// Function to mark a registration as missed
#[ic_cdk::update]
fn mark_registration_as_missed(payload: MarkRegistrationAsMissedPayload) -> Result<Registration, String> {
    // Ensure all required fields are provided
    if payload.admin_password.is_empty() {
        return Err("Invalid input: Ensure 'admin_id', 'admin_password', and 'registration_id' are provided and are of the correct types.".to_string());
    }

    // Validate the passed admin password to ensure it matches the stored admin password
    let registration = REGISTRATIONS_STORAGE.with(|storage| storage.borrow().get(&payload.registration_id));
    match registration {
        Some(registration) => {
            let is_valid_password =
                validate_admin_password(registration.admin_id, &payload.admin_password)?;
            if !is_valid_password {
                return Err(
                    "Invalid password: The provided password does not match the stored password."
                        .to_string(),
                );
            }
        }
        None => {
            return Err(
                "Invalid input: Registration with the provided ID does not exist.".to_string(),
            )
        }
    }

    // Update the registration status to Missed
    let registration = REGISTRATIONS_STORAGE.with(|storage| {
        let mut registration = storage.borrow().get(&payload.registration_id).unwrap().clone();
        registration.status = RegistrationStatus::Missed;
        storage
            .borrow_mut()
            .insert(payload.registration_id, registration.clone());
        registration
    });

    Ok(registration)
}

// Function to retrieve all registrations
#[ic_cdk::query]
fn get_all_registrations() -> Result<Vec<Registration>, String> {
    let registrations = REGISTRATIONS_STORAGE.with(|storage| {
        storage
            .borrow()
            .iter()
            .map(|(_, registration)| registration.clone())
            .collect::<Vec<Registration>>()
    });

    if registrations.is_empty() {
        return Err("No registrations found.".to_string());
    } else {
        Ok(registrations)
    }
}

// Function to create new feedback
#[ic_cdk::update]
fn create_feedback(payload: FeedbackPayload) -> Result<Feedback, String> {
    if payload.feedback.is_empty() || payload.rating < 1 || payload.rating > 10 {
        return Err("Invalid input: Ensure 'volunteer_id', 'event_id', 'feedback', and 'rating' are provided and are of the correct types.".to_string());
    }

    // Validate the volunteer id to ensure it exists and the volunteer has attended the event
    let registration = REGISTRATIONS_STORAGE.with(|storage| {
        storage.borrow().iter().find(|(_, registration)| {
            registration.volunteer_id == payload.volunteer_id
                && registration.event_id == payload.event_id
                && registration.status == RegistrationStatus::Attended
        })
    });

    match registration {
        Some(_) => (),
        None => {
            return Err(
                "Invalid input: Volunteer with the provided ID has not attended the event."
                    .to_string(),
            )
        }
    }

    // Validate the event_id to ensure it exists
    let event = EVENTS_STORAGE.with(|storage| storage.borrow().get(&payload.event_id));
    match event {
        Some(_) => (),
        None => return Err("Invalid input: Event with the provided ID does not exist.".to_string()),
    }

    // Create a new feedback
    let feedback = Feedback {
        id: generate_id(),
        volunteer_id: payload.volunteer_id,
        event_id: payload.event_id,
        feedback: payload.feedback,
        rating: payload.rating,
        created_at: get_current_time(),
    };

    FEEDBACKS_STORAGE.with(|storage| storage.borrow_mut().insert(feedback.id, feedback.clone()));
    Ok(feedback)
}

// Function to retrieve feedback for a specific event
#[ic_cdk::query]
fn get_feedback_by_event_id(event_id: u64) -> Result<Vec<Feedback>, String> {
    let feedbacks = FEEDBACKS_STORAGE.with(|storage| {
        storage
            .borrow()
            .iter()
            .filter(|(_, feedback)| feedback.event_id == event_id)
            .map(|(_, feedback)| feedback.clone())
            .collect::<Vec<Feedback>>()
    });
    
    if feedbacks.is_empty() {
        return Err("No feedback found.".to_string());
    } else {
        Ok(feedbacks)
    }
}

// Function to retrieve all feedback
#[ic_cdk::query]
fn get_all_feedbacks() -> Result<Vec<Feedback>, String> {
    let feedbacks = FEEDBACKS_STORAGE.with(|storage| {
        storage
            .borrow()
            .iter()
            .map(|(_, feedback)| feedback.clone())
            .collect::<Vec<Feedback>>()
    });

    if feedbacks.is_empty() {
        return Err("No feedback found.".to_string());
    } else {
        Ok(feedbacks)
    }
}

// Export the candid interface
ic_cdk::export_candid!();
