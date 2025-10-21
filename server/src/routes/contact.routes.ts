import { Router } from "express";
import { createContact, listContacts, updateContact, deleteContact } from "../controllers/contact.controller";
import { authentication } from "../middlewares/authentication"; // ✅ usa o nome correto

const router = Router();

router.post("/", authentication, createContact);
router.post("/list", authentication, listContacts);
router.put("/:id", authentication, updateContact);
router.delete("/:id", authentication, deleteContact);

export default router;
