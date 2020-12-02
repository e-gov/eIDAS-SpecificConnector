package ee.ria.eidas.connector.specific.responder.metadata;

import ee.ria.eidas.connector.specific.config.SpecificConnectorProperties;
import ee.ria.eidas.connector.specific.responder.saml.OpenSAMLUtils;
import lombok.AccessLevel;
import lombok.NoArgsConstructor;
import org.opensaml.saml.saml2.metadata.*;

import java.util.Collections;
import java.util.List;
import java.util.Optional;
import java.util.Set;

import static java.util.stream.Collectors.toList;
import static org.apache.commons.lang.StringUtils.isNotBlank;
import static org.hibernate.validator.internal.util.CollectionHelper.asSet;
import static org.opensaml.saml.saml2.metadata.ContactPersonTypeEnumeration.*;
import static org.springframework.util.CollectionUtils.isEmpty;

@NoArgsConstructor(access = AccessLevel.PRIVATE)
public class OrganizationContactFactory {
    private static final Set<ContactPersonTypeEnumeration> CONTACT_TYPES = asSet(SUPPORT, TECHNICAL, ADMINISTRATIVE, BILLING, OTHER);

    public static Organization createOrganization(SpecificConnectorProperties.Organization organization) {
        Organization samlOrganization = OpenSAMLUtils.buildObject(Organization.class);
        OrganizationDisplayName odn = OpenSAMLUtils.buildObject(OrganizationDisplayName.class);
        odn.setValue(organization.getDisplayName());
        odn.setXMLLang("en");
        samlOrganization.getDisplayNames().add(odn);

        OrganizationName on = OpenSAMLUtils.buildObject(OrganizationName.class);
        on.setValue(organization.getName());
        on.setXMLLang("en");
        samlOrganization.getOrganizationNames().add(on);

        OrganizationURL url = OpenSAMLUtils.buildObject(OrganizationURL.class);
        url.setValue(organization.getUrl());
        url.setXMLLang("en");
        samlOrganization.getURLs().add(url);
        return samlOrganization;
    }

    public static List<ContactPerson> createContacts(List<SpecificConnectorProperties.Contact> contacts) {
        return isEmpty(contacts) ? Collections.emptyList() : contacts.stream()
                .map(OrganizationContactFactory::createContact)
                .collect(toList());
    }

    private static ContactPerson createContact(SpecificConnectorProperties.Contact contact) {
        ContactPerson contactPerson = OpenSAMLUtils.buildObject(ContactPerson.class);
        Optional<ContactPersonTypeEnumeration> contactType = CONTACT_TYPES.stream().filter(t -> t.toString().equals(contact.getType())).findFirst();
        contactType.ifPresent(contactPerson::setType);

        EmailAddress emailAddress = OpenSAMLUtils.buildObject(EmailAddress.class);
        emailAddress.setAddress(contact.getEmail());
        contactPerson.getEmailAddresses().add(emailAddress);

        if (isNotBlank(contact.getCompany())) {
            Company company = OpenSAMLUtils.buildObject(Company.class);
            company.setName(contact.getCompany());
            contactPerson.setCompany(company);
        }

        if (isNotBlank(contact.getGivenName())) {
            GivenName givenName = OpenSAMLUtils.buildObject(GivenName.class);
            givenName.setName(contact.getGivenName());
            contactPerson.setGivenName(givenName);
        }

        if (isNotBlank(contact.getSurname())) {
            SurName surName = OpenSAMLUtils.buildObject(SurName.class);
            surName.setName(contact.getSurname());
            contactPerson.setSurName(surName);
        }

        if (isNotBlank(contact.getPhone())) {
            TelephoneNumber phoneNumber = OpenSAMLUtils.buildObject(TelephoneNumber.class);
            phoneNumber.setNumber(contact.getPhone());
            contactPerson.getTelephoneNumbers().add(phoneNumber);
        }

        return contactPerson;
    }
}
